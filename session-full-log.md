# 전체 작업 로그 — ML 클러스터 구축 (2026-07-18 ~ 07-20)

목표: 3090×7(GPU) + VM×17(CPU)로 Qwen3-235B 분산 서빙 + RAG(Saem) 시스템 구축.
아래는 실제로 실행한 터미널 명령어와 파이썬 코드를 순서대로 정리한 것. 동일 명령 재시도는 "(N회 재시도)"로 표기하고 마지막 성공 버전만 남김.

---

## 0. 사전 준비 — SSH 키, 네트워크 테스트

### SSH 키 저장 (camp-7)
```bash
nano ~/.ssh/ml_master   # 개인키 붙여넣기
chmod 600 ~/.ssh/ml_master
```

### 키 손상 시 복구 (한 줄로 뭉친 경우)
```bash
wc -l ~/.ssh/ml_master
head -1 ~/.ssh/ml_master
tail -1 ~/.ssh/ml_master
```
```bash
python3 << 'EOF'
raw = open('/root/.ssh/ml_master').read().strip()
begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
end   = "-----END OPENSSH PRIVATE KEY-----"
body = raw.replace(begin,"").replace(end,"").replace("\n","").replace("\r","").replace(" ","").strip()
lines = [body[i:i+64] for i in range(0,len(body),64)]
open('/root/.ssh/ml_master','w').write(begin+"\n" + "\n".join(lines) + "\n" + end+"\n")
print("완료. 총 줄 수:", len(lines)+2)
EOF
chmod 600 ~/.ssh/ml_master
```

### SSH config 등록 (매번 -i 안 쳐도 되게)
```bash
cat >> ~/.ssh/config << 'EOF'
Host 192.168.0.* 172.10.5.*
    User root
    IdentityFile ~/.ssh/ml_master
    StrictHostKeyChecking no
EOF
chmod 600 ~/.ssh/config
```

### 네트워크 지연/대역폭 테스트 (camp-7 ↔ 0.83)
```bash
ping 192.168.0.83
```
```bash
sudo apt update && sudo apt install -y iperf3
```
```bash
iperf3 -s          # 서버2(0.83)에서
```
```bash
iperf3 -c 192.168.0.83   # camp-7에서
```

---

## 1. 1차 시도 — 72B, 2~3노드 (나중에 235B/7노드로 전환됨)

### 모델/패키지 설치
```bash
pip install -U "huggingface_hub[cli]"
hf download Qwen/Qwen2.5-72B-Instruct-AWQ
```
```bash
pip install "ray[default]"
```

### Ray 클러스터 (헤드 + 워커)
```bash
ray start --head --port=6379 --min-worker-port=20000 --max-worker-port=21000
```
```bash
ray start --address='192.168.0.228:6379' --min-worker-port=20000 --max-worker-port=21000
```
```bash
ray status
```

### vLLM 기동 (pp=2, 최초 시도 — tensor_parallel_size 오타로 실패했다가 pipeline으로 수정)
```bash
vllm serve Qwen/Qwen2.5-72B-Instruct-AWQ \
  --quantization awq \
  --tensor-parallel-size 1 \
  --pipeline-parallel-size 2 \
  --distributed-executor-backend ray \
  --gpu-memory-utilization 0.90 \
  --max-model-len 8192 \
  --served-model-name qwen2.5-72b-assistant \
  --host 0.0.0.0 \
  --port 8000
```

### Ollama 충돌 진단/정리 (GPU 메모리 점유)
```bash
nvidia-smi
```
```bash
systemctl status ollama
journalctl -u ollama -n 50 --no-pager
```
```bash
sudo systemctl stop ollama
sudo systemctl disable ollama
```

### 메모리 부족 재시도 (AWQ 변환 OOM 대응)
```bash
PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True vllm serve Qwen/Qwen2.5-72B-Instruct-AWQ \
  --quantization awq \
  --tensor-parallel-size 1 \
  --pipeline-parallel-size 2 \
  --distributed-executor-backend ray \
  --gpu-memory-utilization 0.85 \
  --max-model-len 4096 \
  --served-model-name qwen2.5-72b-assistant \
  --host 0.0.0.0 \
  --port 8000
```

### 3번째 노드(camp-6) 추가 → pp=3
```bash
pip install -U "huggingface_hub[cli]" "ray[default]" vllm
hf download Qwen/Qwen2.5-72B-Instruct-AWQ
```
```bash
ray start --address='192.168.0.228:6379' --min-worker-port=20000 --max-worker-port=21000
```
```bash
vllm serve Qwen/Qwen2.5-72B-Instruct-AWQ \
  --quantization awq \
  --tensor-parallel-size 1 \
  --pipeline-parallel-size 3 \
  --distributed-executor-backend ray \
  --gpu-memory-utilization 0.85 \
  --max-model-len 8192 \
  --served-model-name qwen2.5-72b-assistant \
  --host 0.0.0.0 \
  --port 8000
```

### 성공 확인
```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5-72b-assistant",
    "messages": [{"role": "user", "content": "안녕! 간단히 자기소개 해줘."}],
    "max_tokens": 200
  }'
```

### tmux / nohup으로 상주화
```bash
tmux new -s vllm
```
```bash
source ~/vllm_env.sh
vllm serve Qwen/Qwen2.5-72B-Instruct-AWQ --quantization awq --tensor-parallel-size 1 \
  --pipeline-parallel-size 3 --distributed-executor-backend ray \
  --gpu-memory-utilization 0.90 --max-model-len 8192 --enforce-eager \
  --served-model-name qwen2.5-72b-assistant --host 0.0.0.0 --port 8000
```
```bash
# tmux 대안
nohup vllm serve Qwen/Qwen2.5-72B-Instruct-AWQ \
  --quantization awq --tensor-parallel-size 1 --pipeline-parallel-size 3 \
  --distributed-executor-backend ray --gpu-memory-utilization 0.90 \
  --max-model-len 8192 --enforce-eager \
  --served-model-name qwen2.5-72b-assistant --host 0.0.0.0 --port 8000 \
  > ~/vllm.log 2>&1 &
disown
```

### 72B 대화/벤치 스크립트

`~/chat.py` (최종본 — 서로게이트 문자 필터 + 에러 출력):
```python
import json, urllib.request, urllib.error

URL = "http://localhost:8000/v1/chat/completions"
messages = []

def sanitize(s):
    return ''.join(ch for ch in s if not (0xD800 <= ord(ch) <= 0xDFFF))

print("Qwen 72B와 대화 시작 (종료: exit 또는 quit)\n")
while True:
    user_input = sanitize(input("나> ").strip())
    if user_input.lower() in ("exit", "quit"):
        break
    if not user_input:
        continue
    messages.append({"role": "user", "content": user_input})
    body = json.dumps({
        "model": "qwen2.5-72b-assistant",
        "messages": messages,
        "max_tokens": 800,
    }).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            resp = json.load(r)
    except urllib.error.HTTPError as e:
        print(f"\n[에러 {e.code}] {e.read().decode()}\n")
        messages.pop()
        continue
    reply = resp["choices"][0]["message"]["content"]
    print(f"\nQwen> {reply}\n")
    messages.append({"role": "assistant", "content": reply})
```

`~/bench.py`:
```python
import json, time, urllib.request

URL = "http://localhost:8000/v1/chat/completions"

def bench(prompt, max_tokens=256):
    body = json.dumps({
        "model": "qwen2.5-72b-assistant",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "stream": True,
    }).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    t0 = time.time(); ttft = None; n = 0
    with urllib.request.urlopen(req) as r:
        for line in r:
            line = line.decode().strip()
            if not line.startswith("data:") or line == "data: [DONE]":
                continue
            chunk = json.loads(line[5:])
            delta = chunk["choices"][0]["delta"].get("content")
            if delta:
                if ttft is None:
                    ttft = time.time() - t0
                n += 1
    total = time.time() - t0
    decode_tps = n / (total - ttft) if ttft and total > ttft else 0
    print(f"  첫 토큰까지(TTFT): {ttft:.2f}s | 생성 토큰: {n} | 총 시간: {total:.2f}s | 생성 속도: {decode_tps:.1f} tok/s")

print("[워밍업]"); bench("안녕", 32)
print("[짧은 질문]"); bench("대한민국의 수도는 어디이고, 그 도시의 특징을 세 가지 알려줘.")
print("[긴 생성]"); bench("인공지능의 역사를 1950년대부터 현재까지 자세히 설명해줘.", 512)
```

---

## 2. GPU 서버 4대 추가 → 총 7대 (camp-8/13/14/15)

### 새 서버 상태 확인 (반복 사용한 템플릿)
```bash
for ip in 172.10.5.126 172.10.5.154 172.10.5.60 172.10.5.86; do
  echo "===== $ip ====="
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$ip \
    "hostname; ip -o -4 addr show | awk '{print \$2, \$4}' | grep -v '127.0.0.1'"
done
```
```bash
for ip in 172.10.5.126 172.10.5.154 172.10.5.60 172.10.5.86; do
  echo "===== $ip ====="
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$ip \
    "hostname; lspci | grep -i nvidia; nproc; free -g | awk '/^Mem:/{print \"RAM: \"\$2\"GB\"}'"
done
```
```bash
ping -c 3 192.168.0.228   # 새 서버 → 헤드 통신 확인
```

### NVIDIA 드라이버 설치 (버전 580, 기존과 통일)
```bash
nvidia-smi --query-gpu=driver_version --format=csv,noheader   # 기존 서버 버전 확인
```
```bash
apt update
apt install -y nvidia-driver-580
```
```bash
reboot
```
```bash
nvidia-smi   # 재부팅 후 확인
```

### vLLM 스택 설치 (4대 각각)
```bash
apt install -y python3-pip
pip install -U "huggingface_hub[cli]" "ray[default]" vllm==0.25.1
pip uninstall -y flashinfer flashinfer-python 2>/dev/null
```

### 공통 환경변수 파일 (7대 전체 동일)
```bash
cat > ~/vllm_env.sh << 'EOF'
export NCCL_SOCKET_IFNAME=ens3
export GLOO_SOCKET_IFNAME=ens3
export VLLM_ATTENTION_BACKEND=FLASH_ATTN
export VLLM_USE_FLASHINFER_SAMPLER=0
export NCCL_DEBUG=WARN
export NCCL_IB_DISABLE=1
export NCCL_P2P_DISABLE=1
export NCCL_NET=Socket
export NCCL_CUMEM_ENABLE=0
EOF
source ~/vllm_env.sh
```

---

## 3. Qwen3-235B 모델 확보

### 리포/구조 확인
```bash
hf download QuantTrio/Qwen3-235B-A22B-Instruct-2507-AWQ --include "*.json" --local-dir ~/qwen3-index
ls -la ~/qwen3-index
```
```bash
python3 -c "
import json
d = json.load(open('/root/qwen3-index/model.safetensors.index.json'))
files = {}
for tensor, f in d['weight_map'].items():
    files.setdefault(f, []).append(tensor)
print('조각 파일 개수:', len(files))
print()
import re
for f in sorted(files):
    layers = set()
    for t in files[f]:
        m = re.search(r'layers\.(\d+)\.', t)
        if m: layers.add(int(m.group(1)))
    rng = f'레이어 {min(layers)}~{max(layers)}' if layers else '(비레이어: embed/norm/lm_head 등)'
    print(f'{f}: {len(files[f])}개 텐서, {rng}')
"
```

### 72B 캐시 정리 (공간 확보)
```bash
ps aux | grep -E "vllm serve" | grep -v grep
pkill -f "vllm serve"
rm -rf ~/.cache/huggingface/hub/models--Qwen--Qwen2.5-72B-Instruct-AWQ
df -h /
```

### 25조각을 7노드에 라운드로빈 분배 계산
```bash
python3 -c "
nodes = ['192.168.0.228','192.168.0.83','192.168.0.57','192.168.0.159','192.168.0.123','192.168.0.157','192.168.0.196']
shards = [f'model-{i:05d}-of-00025.safetensors' for i in range(1,26)]
for idx, s in enumerate(shards):
    print(f'{s} -> {nodes[idx % len(nodes)]}')
"
```

### 분산 다운로드 스크립트 (`~/distribute_download.sh`)
```bash
cat > ~/distribute_download.sh << 'SCRIPT'
#!/bin/bash
REPO="QuantTrio/Qwen3-235B-A22B-Instruct-2507-AWQ"
MODELDIR="/root/qwen3-model"
KEY="/root/.ssh/ml_master"
NODES=(192.168.0.228 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196)

for i in $(seq 1 25); do
  shard=$(printf "model-%05d-of-00025.safetensors" $i)
  node=${NODES[$(( (i-1) % 7 ))]}
  echo "$shard $node" >> /tmp/shardmap.txt
done

for n in "${NODES[@]}"; do
  patterns=$(awk -v node="$n" '$2==node{printf "--include %s ", $1}' /tmp/shardmap.txt)
  echo "===== $n : 다운로드 시작 ====="
  ssh -i $KEY -o StrictHostKeyChecking=no root@$n \
    "mkdir -p $MODELDIR && cd $MODELDIR && hf download $REPO --include '*.json' $patterns --local-dir $MODELDIR > /tmp/dl.log 2>&1 && echo '$n 완료' || echo '$n 실패'" &
done
wait
echo "===== 전체 다운로드 완료 ====="
SCRIPT

rm -f /tmp/shardmap.txt
chmod +x ~/distribute_download.sh
bash ~/distribute_download.sh
```

### 다운로드 진행 확인 (여러 번 재실행)
```bash
for n in 192.168.0.228 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196; do
  echo -n "$n: "
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$n \
    "ls /root/qwen3-model/*.safetensors 2>/dev/null | wc -l | tr -d '\n'; echo -n ' 조각, '; du -sh /root/qwen3-model 2>/dev/null | cut -f1"
done
```

---

## 4. NFS 분산 저장 구성

### 각 노드가 자기 조각을 export (`~/setup_nfs.sh`)
```bash
cat > ~/setup_nfs.sh << 'SCRIPT'
#!/bin/bash
KEY="/root/.ssh/ml_master"
NODES=(192.168.0.228 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196)
for n in "${NODES[@]}"; do
  echo "===== $n : NFS 서버 설정 ====="
  ssh -i $KEY -o StrictHostKeyChecking=no root@$n "
    apt-get install -y nfs-kernel-server >/dev/null 2>&1
    echo '/root/qwen3-model 192.168.0.0/24(ro,sync,no_subtree_check,no_root_squash)' > /etc/exports
    exportfs -ra
    systemctl restart nfs-kernel-server
    echo '$n export 완료'
  "
done
SCRIPT
chmod +x ~/setup_nfs.sh
bash ~/setup_nfs.sh
```

### 설치/export 검증 및 재시도 (일부 노드 실패분)
```bash
for n in 192.168.0.228 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196; do
  echo -n "$n: "
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$n "dpkg -l | grep -q nfs-kernel-server && echo -n '설치됨 ' || echo -n '미설치 '; systemctl is-active nfs-kernel-server 2>/dev/null"
done
```
```bash
for n in 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157; do
  echo "===== $n ====="
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$n "apt-get update -qq && apt-get install -y nfs-kernel-server 2>&1 | tail -4"
done
```
```bash
for n in 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157; do
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$n "
    echo '/root/qwen3-model 192.168.0.0/24(ro,sync,no_subtree_check,no_root_squash)' > /etc/exports
    exportfs -ra
    exportfs -v | grep -q qwen3-model && echo 'export OK' || echo 'export 실패'
  "
done
```

### 상호 마운트 + 통합 폴더 링크 (`~/mount_shards.sh`)
```bash
cat > ~/mount_shards.sh << 'SCRIPT'
#!/bin/bash
KEY="/root/.ssh/ml_master"
NODES=(192.168.0.228 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196)

for me in "${NODES[@]}"; do
  echo "===== $me : 마운트 + 통합 ====="
  ssh -i $KEY -o StrictHostKeyChecking=no root@$me "
    apt-get install -y nfs-common >/dev/null 2>&1
    rm -rf /root/qwen3-full && mkdir -p /root/qwen3-full
    ln -sf /root/qwen3-model/*.safetensors /root/qwen3-full/ 2>/dev/null
    ln -sf /root/qwen3-model/*.json /root/qwen3-full/ 2>/dev/null
    for other in ${NODES[@]}; do
      if [ \"\$other\" != \"$me\" ]; then
        mkdir -p /mnt/\$other
        mountpoint -q /mnt/\$other || mount -t nfs \$other:/root/qwen3-model /mnt/\$other 2>/dev/null
        ln -sf /mnt/\$other/*.safetensors /root/qwen3-full/ 2>/dev/null
      fi
    done
    echo -n '  통합 조각 개수: '; ls /root/qwen3-full/*.safetensors 2>/dev/null | wc -l
  "
done
SCRIPT
chmod +x ~/mount_shards.sh
bash ~/mount_shards.sh
```

### 링크/읽기 검증
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.83 "
  cd /root/qwen3-full
  echo -n '안 깨진 링크: '; find . -type l -xtype f | wc -l
  echo -n '깨진 링크: '; find . -type l ! -xtype f | wc -l
  ls model.safetensors.index.json config.json 2>/dev/null
"
```
```bash
for n in 192.168.0.228 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196; do
  echo -n "$n: "
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$n "head -c 100 /root/qwen3-full/model-00001-of-00025.safetensors >/dev/null 2>&1 && echo '읽기 OK' || echo '읽기 실패 ⚠️'"
done
```

### 0.83 stale 마운트 복구 (vLLM 첫 시도 실패 후)
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.83 "
  for m in /mnt/192.168.0.*; do umount -f -l \$m 2>/dev/null; done
  for other in 192.168.0.228 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196; do
    mkdir -p /mnt/\$other
    mount -t nfs \$other:/root/qwen3-model /mnt/\$other 2>/dev/null
  done
  rm -rf /root/qwen3-full && mkdir -p /root/qwen3-full
  ln -sf /root/qwen3-model/*.safetensors /root/qwen3-full/ 2>/dev/null
  ln -sf /root/qwen3-model/*.json /root/qwen3-full/ 2>/dev/null
  for other in 192.168.0.228 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196; do
    ln -sf /mnt/\$other/*.safetensors /root/qwen3-full/ 2>/dev/null
  done
  echo -n '조각 개수: '; ls /root/qwen3-full/*.safetensors 2>/dev/null | wc -l
  echo -n 'model-00001 읽기: '; head -c 100 /root/qwen3-full/model-00001-of-00025.safetensors >/dev/null 2>&1 && echo 'OK' || echo '실패'
"
```

---

## 5. Ray 7노드 클러스터

### 전체 초기화 (반복 사용, 유령/중복 노드 문제 해결용)
```bash
for n in 192.168.0.228 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196; do
  echo "===== $n 정지 ====="
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$n "
    ray stop --force >/dev/null 2>&1
    pkill -9 -f raylet 2>/dev/null
    pkill -9 -f 'ray::' 2>/dev/null
    pkill -9 -f vllm 2>/dev/null
    rm -rf /tmp/ray
    echo '정지 완료'
  "
done
```

### 헤드 시작
```bash
source ~/vllm_env.sh
ray start --head --port=6379 --min-worker-port=20000 --max-worker-port=21000
```

### 워커 6대 순차/일괄 조인
```bash
for n in 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196; do
  echo "===== $n 조인 ====="
  ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no root@$n "
    source ~/vllm_env.sh
    ray start --address='192.168.0.228:6379' --min-worker-port=20000 --max-worker-port=21000 2>&1 | tail -3
  "
done
```

### 클러스터 상태 검증 (반복 사용)
```bash
ray status
```
```bash
ray list nodes
```
```bash
ray list nodes --format json 2>/dev/null | python3 -c "
import json,sys
nodes = json.load(sys.stdin)
alive = {}
dead = 0
for n in nodes:
    if n.get('state')=='ALIVE':
        ip = n.get('node_ip')
        alive[ip] = alive.get(ip,0)+1
    else:
        dead += 1
print('=== ALIVE 노드 (IP별) ===')
for ip,c in sorted(alive.items()):
    print(f'  {ip}: {c}개', '  ⚠️중복!' if c>1 else '')
print(f'ALIVE 총: {sum(alive.values())}개 / DEAD: {dead}개')
"
```

### 0.83 중복 조인 문제 해결 (재부팅)
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.83 "reboot" 2>/dev/null
```
```bash
sleep 90
for ip in 192.168.0.83; do
  ssh -i ~/.ssh/ml_master root@$ip "nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader"
done
```
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.83 "
  source ~/vllm_env.sh
  ray start --address='192.168.0.228:6379' --min-worker-port=20000 --max-worker-port=21000
"
```

---

## 6. vLLM으로 235B 기동

```bash
tmux new -s qwen3
```

### 최초 시도 (0.83 stale NFS 마운트로 실패 — FileNotFoundError)
```bash
source ~/vllm_env.sh
vllm serve /root/qwen3-full \
  --tensor-parallel-size 1 \
  --pipeline-parallel-size 7 \
  --distributed-executor-backend ray \
  --gpu-memory-utilization 0.90 \
  --max-model-len 8192 \
  --enforce-eager \
  --served-model-name qwen3-235b \
  --trust-remote-code \
  --host 0.0.0.0 --port 8000 2>&1 | tee ~/qwen3_boot.log
```

### 로그 진단
```bash
tmux capture-pane -t qwen3 -p -S -3000 | grep -iE "error|not found|no such|out of memory|oom|shape|mismatch|assert|nccl|unsupported|KeyError|ValueError" | grep -v "core.py:1231\|raise\|return\|File \"" | head -40
```

### NFS 복구(위 5절 참고) 후 재시도 — 성공
```bash
tmux attach -t qwen3 2>/dev/null || tmux new -s qwen3
```
```bash
source ~/vllm_env.sh
vllm serve /root/qwen3-full \
  --tensor-parallel-size 1 \
  --pipeline-parallel-size 7 \
  --distributed-executor-backend ray \
  --gpu-memory-utilization 0.90 \
  --max-model-len 8192 \
  --enforce-eager \
  --served-model-name qwen3-235b \
  --trust-remote-code \
  --host 0.0.0.0 --port 8000 2>&1 | tee ~/qwen3_boot.log
```
→ `Application startup complete` 확인.

### 모델 신원/물리 증거 확인
```bash
python3 -c "
import json
c = json.load(open('/root/qwen3-full/config.json'))
print('아키텍처:', c.get('architectures'))
print('레이어 수:', c.get('num_hidden_layers'))
print('hidden_size:', c.get('hidden_size'))
print('전문가 수(MoE):', c.get('num_experts'))
print('활성 전문가:', c.get('num_experts_per_tok'))
print('양자화:', c.get('quantization_config', {}).get('quant_method'))
"
```
```bash
for n in 192.168.0.228 192.168.0.83 192.168.0.57 192.168.0.159 192.168.0.123 192.168.0.157 192.168.0.196; do
  echo -n "$n: "
  ssh -i ~/.ssh/ml_master root@$n "nvidia-smi --query-gpu=memory.used --format=csv,noheader"
done
```

---

## 7. 235B 테스트/벤치마크

### API 호출 테스트
```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen3-235b",
    "messages": [{"role": "user", "content": "안녕! 너는 어떤 모델이야? 한국어로 간단히 자기소개 해줘."}],
    "max_tokens": 300
  }'
```

### `~/chat3.py` (최종본 — 여러 줄 입력 + 스트리밍 출력)
```python
import json, urllib.request, urllib.error

URL = "http://localhost:8000/v1/chat/completions"
messages = []

def sanitize(s):
    return ''.join(ch for ch in s if not (0xD800 <= ord(ch) <= 0xDFFF))

print("Qwen3-235B 대화 (한 줄 입력=전송 / 여러 줄은 붙여넣고 빈 줄에서 Enter)")
print("명령: exit=종료\n")

while True:
    print("나> (입력 후, 여러 줄이면 마지막에 빈 줄)")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            line = ""
        if line == "":
            break
        lines.append(line)
    user_input = sanitize("\n".join(lines).strip())
    if not user_input:
        continue
    if user_input.lower() in ("exit", "quit"):
        break
    messages.append({"role": "user", "content": user_input})
    body = json.dumps({"model": "qwen3-235b", "messages": messages,
                       "max_tokens": 1500, "stream": True}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    print("\nQwen3> ", end="", flush=True)
    reply = ""
    try:
        with urllib.request.urlopen(req) as r:
            for raw in r:
                raw = raw.decode().strip()
                if not raw.startswith("data:") or raw == "data: [DONE]":
                    continue
                delta = json.loads(raw[5:])["choices"][0]["delta"].get("content")
                if delta:
                    print(delta, end="", flush=True)
                    reply += delta
    except urllib.error.HTTPError as e:
        print(f"\n[에러 {e.code}] {e.read().decode()}")
        messages.pop(); continue
    print("\n")
    messages.append({"role": "assistant", "content": reply})
```

### `~/bench3.py`
```python
import json, time, urllib.request

URL = "http://localhost:8000/v1/chat/completions"

def bench(prompt, max_tokens=256):
    body = json.dumps({
        "model": "qwen3-235b",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "stream": True,
    }).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    t0 = time.time(); ttft = None; n = 0
    with urllib.request.urlopen(req) as r:
        for line in r:
            line = line.decode().strip()
            if not line.startswith("data:") or line == "data: [DONE]":
                continue
            chunk = json.loads(line[5:])
            delta = chunk["choices"][0]["delta"].get("content")
            if delta:
                if ttft is None: ttft = time.time() - t0
                n += 1
    total = time.time() - t0
    tps = n / (total - ttft) if ttft and total > ttft else 0
    print(f"  첫토큰 {ttft:.2f}s | 생성 {n}토큰 | 총 {total:.1f}s | 속도 {tps:.1f} tok/s")

print("[워밍업]"); bench("안녕", 20)
print("[중간 질문]"); bench("파이썬으로 퀵소트 구현해줘", 300)
print("[긴 생성]"); bench("객체지향 프로그래밍의 4대 특징을 각각 예시와 함께 설명해줘", 600)
```

**실측 결과**: TTFT 0.14~1.0s / 속도 7.7~7.9 tok/s (`--enforce-eager` 상태 기준)

---

## 8. Saem RAG 시스템 (VM 17대: camp-57~73)

### VM 인벤토리 조사 (`~/vm_survey.sh`)
```bash
cat > ~/vm_survey.sh << 'SCRIPT'
#!/bin/bash
VMS=(172.10.7.240 172.10.7.93 172.10.7.128 172.10.7.124 172.10.7.137 172.10.7.241 172.10.7.162 172.10.7.166 172.10.7.19 172.10.7.17 172.10.7.130 172.10.7.237 172.10.7.97 172.10.7.210 172.10.7.146 172.10.7.246 172.10.7.33)
for ip in "${VMS[@]}"; do
  echo "===== $ip ====="
  timeout 10 ssh -i ~/.ssh/ml_master -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$ip "
    echo \"호스트: \$(hostname) | 내부IP: \$(hostname -I | tr ' ' ',')\"
    echo \"CPU: \$(nproc)코어 | RAM여유: \$(free -g | awk '/^Mem:/{print \$7}')GB | 디스크여유: \$(df -h / | awk 'NR==2{print \$4}')\"
    ping -c1 -W1 192.168.0.228 >/dev/null 2>&1 && echo '235B 도달: OK' || echo '235B 도달: 실패'
  " 2>/dev/null || echo "  ⚠️ SSH 접속 실패"
done
SCRIPT
chmod +x ~/vm_survey.sh
bash ~/vm_survey.sh
```

### Qdrant 설치 — 도커 시도(사용자가 비도커로 전환)
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.252 '
  apt-get update -qq && apt-get install -y docker.io >/dev/null 2>&1
  systemctl enable --now docker >/dev/null 2>&1
  docker run -d --name qdrant --restart unless-stopped \
    -p 6333:6333 \
    -v /root/qdrant_storage:/qdrant/storage \
    qdrant/qdrant
  sleep 10
  curl -s http://localhost:6333/ && echo " <- Qdrant OK"
'
```

### Qdrant 설치 — 바이너리(최신판 GLIBC 비호환 → 버전 낮춰가며 탐색, v1.12.6에서 성공)
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.252 '
  cd ~/qdrant && rm -f qdrant qdrant-*.tar.gz
  for ver in v1.13.6 v1.12.6 v1.11.5 v1.9.7; do
    echo "=== $ver 시도 ==="
    wget -q https://github.com/qdrant/qdrant/releases/download/$ver/qdrant-x86_64-unknown-linux-gnu.tar.gz || { echo "다운로드 실패"; continue; }
    tar xzf qdrant-x86_64-unknown-linux-gnu.tar.gz
    if ./qdrant --version 2>/dev/null; then
      echo ">>> $ver 호환, 서버 시작"
      nohup ./qdrant > qdrant.log 2>&1 &
      sleep 6
      curl -s http://localhost:6333/ && echo " <- Qdrant OK ($ver)"
      break
    else
      echo "$ver 비호환, 다음"
      rm -f qdrant qdrant-*.tar.gz
    fi
  done
'
```

### camp-59 파이썬 환경 (임베딩+게이트웨이)
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.209 '
  apt-get install -y python3-pip >/dev/null 2>&1
  pip install -q fastembed qdrant-client fastapi uvicorn requests
  python3 -c "import fastembed, qdrant_client; print(\"환경 OK\")"
'
```

### 색인 스크립트 v1 — e5-large (RAM 3GB OOM으로 실패)
```python
import os, hashlib, uuid
from fastembed import TextEmbedding
from qdrant_client import QdrantClient, models

QDRANT = "http://192.168.0.252:6333"
SRC = "/root/docs"
COLL = "knowledge"
EXTS = (".py", ".m", ".md", ".txt", ".r", ".cpp", ".h", ".ipynb", ".js")

print("임베딩 모델 로딩(최초엔 다운로드로 몇 분)...")
model = TextEmbedding("intfloat/multilingual-e5-large")
client = QdrantClient(url=QDRANT, timeout=60)

if not client.collection_exists(COLL):
    client.create_collection(COLL,
        vectors_config=models.VectorParams(size=1024, distance=models.Distance.COSINE))

def chunks(path, size=800, overlap=100):
    try: text = open(path, encoding="utf-8", errors="ignore").read()
    except: return
    step = size - overlap
    for i in range(0, max(len(text), 1), step):
        c = text[i:i+size].strip()
        if c: yield i, c

batch_texts, batch_meta = [], []
total = 0
def flush():
    global batch_texts, batch_meta, total
    if not batch_texts: return
    vecs = list(model.embed(batch_texts))
    pts = []
    for (path, off, txt), v in zip(batch_meta, vecs):
        key = hashlib.sha256(f"{path}:{off}:{txt}".encode()).hexdigest()
        pts.append(models.PointStruct(id=str(uuid.UUID(key[:32])),
            vector=v.tolist(), payload={"path": path, "offset": off, "text": txt}))
    client.upsert(COLL, pts)
    total += len(pts)
    print(f"  적재 {total}개...")
    batch_texts, batch_meta = [], []

for root, _, files in os.walk(SRC):
    if ".git" in root: continue
    for f in files:
        if not f.endswith(EXTS): continue
        p = os.path.join(root, f)
        for off, c in chunks(p):
            batch_texts.append(c)
            batch_meta.append((p.replace(SRC+"/",""), off, c))
            if len(batch_texts) >= 32: flush()
flush()
print(f"색인 완료: 총 {total}청크 / Qdrant 보유: {client.count(COLL).count}")
```

### 저장소 클론 + 위 스크립트 실행
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.209 'bash -s' << 'OUTER'
apt-get install -y git >/dev/null 2>&1
rm -rf /root/docs && mkdir -p /root/docs
git clone --depth 1 https://github.com/Chekoon777/EyeMovementEventDetectionAlgorithms.git /root/docs/eyemove
echo "=== 클론된 파일 수: $(find /root/docs -type f | wc -l)"
# (여기에 위 index.py 작성)
python3 /root/index.py
OUTER
```

### `~/index.py` 최종본 — MiniLM(384차원)으로 교체, OOM 해결
```python
import os, hashlib, uuid
from fastembed import TextEmbedding
from qdrant_client import QdrantClient, models

QDRANT = "http://192.168.0.252:6333"
SRC = "/root/docs"
COLL = "knowledge"
EXTS = (".py", ".m", ".md", ".txt", ".r", ".cpp", ".h", ".ipynb", ".js")
MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
DIM = 384

print("임베딩 모델 로딩...", flush=True)
model = TextEmbedding(MODEL)
client = QdrantClient(url=QDRANT, timeout=60, check_compatibility=False)

if client.collection_exists(COLL):
    client.delete_collection(COLL)
client.create_collection(COLL,
    vectors_config=models.VectorParams(size=DIM, distance=models.Distance.COSINE))

def chunks(path, size=800, overlap=100):
    try: text = open(path, encoding="utf-8", errors="ignore").read()
    except: return
    for i in range(0, max(len(text), 1), size - overlap):
        c = text[i:i+size].strip()
        if c: yield i, c

batch_t, batch_m, total = [], [], 0
def flush():
    global batch_t, batch_m, total
    if not batch_t: return
    vecs = list(model.embed(batch_t))
    pts = []
    for (path, off, txt), v in zip(batch_m, vecs):
        key = hashlib.sha256(f"{path}:{off}:{txt}".encode()).hexdigest()
        pts.append(models.PointStruct(id=str(uuid.UUID(key[:32])),
            vector=v.tolist(), payload={"path": path, "offset": off, "text": txt}))
    client.upsert(COLL, pts)
    total += len(pts)
    print(f"  적재 {total}개...", flush=True)
    batch_t, batch_m = [], []

for root, _, files in os.walk(SRC):
    if ".git" in root: continue
    for f in files:
        if not f.endswith(EXTS): continue
        p = os.path.join(root, f)
        for off, c in chunks(p):
            batch_t.append(c); batch_m.append((p.replace(SRC+"/",""), off, c))
            if len(batch_t) >= 16: flush()
flush()
print(f"색인 완료: 총 {total}청크 / Qdrant 보유: {client.count(COLL).count}", flush=True)
```
```bash
python3 -u /root/index.py
```
→ 결과: 654청크 색인 완료

### `~/search_test.py` (qdrant-client 1.18 API 변경 대응 — query_points 사용)
```python
from fastembed import TextEmbedding
from qdrant_client import QdrantClient

model = TextEmbedding("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
client = QdrantClient(url="http://192.168.0.252:6333", timeout=60, check_compatibility=False)

for q in ["saccade 검출 알고리즘", "fixation을 분류하는 코드", "데이터 전처리는 어디서 해?"]:
    vec = list(model.embed([q]))[0].tolist()
    hits = client.query_points("knowledge", query=vec, limit=3).points
    print(f"\n질문: {q}")
    for h in hits:
        print(f"  [{h.score:.3f}] {h.payload['path']} (offset {h.payload['offset']})")
```

### `~/gateway.py` v1 (camp-59, 단발 질문)
```python
from fastembed import TextEmbedding
from qdrant_client import QdrantClient
from fastapi import FastAPI
import urllib.request, json

QDRANT = "http://192.168.0.252:6333"
VLLM   = "http://192.168.0.228:8000/v1/chat/completions"
COLL   = "knowledge"

model = TextEmbedding("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
client = QdrantClient(url=QDRANT, timeout=60, check_compatibility=False)
app = FastAPI()

@app.post("/ask")
def ask(body: dict):
    q = body["question"]
    vec = list(model.embed([q]))[0].tolist()
    hits = client.query_points(COLL, query=vec, limit=5).points
    ctx = "\n\n---\n\n".join(f"[출처: {h.payload['path']}]\n{h.payload['text']}" for h in hits)
    prompt = (f"아래는 코드 저장소에서 검색된 관련 조각들이다. 이 자료를 근거로 질문에 답하고, "
              f"어느 파일을 참고했는지 출처를 명시해라.\n\n{ctx}\n\n질문: {q}")
    req = urllib.request.Request(VLLM,
        data=json.dumps({"model": "qwen3-235b",
                         "messages": [{"role": "user", "content": prompt}],
                         "max_tokens": 1200}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        ans = json.load(r)["choices"][0]["message"]["content"]
    return {"answer": ans, "sources": list({h.payload["path"] for h in hits})}
```
```bash
nohup python3 -u -m uvicorn gateway:app --host 0.0.0.0 --port 9000 --app-dir /root > /root/gateway.log 2>&1 &
```

### `~/gateway.py` v2 (대화 히스토리 지원)
```python
from fastembed import TextEmbedding
from qdrant_client import QdrantClient
from fastapi import FastAPI
import urllib.request, json

QDRANT = "http://192.168.0.252:6333"
VLLM   = "http://192.168.0.228:8000/v1/chat/completions"
COLL   = "knowledge"

model = TextEmbedding("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
client = QdrantClient(url=QDRANT, timeout=60, check_compatibility=False)
app = FastAPI()

@app.post("/ask")
def ask(body: dict):
    q = body["question"]
    history = body.get("history", [])
    vec = list(model.embed([q]))[0].tolist()
    hits = client.query_points(COLL, query=vec, limit=5).points
    ctx = "\n\n---\n\n".join(f"[출처: {h.payload['path']}]\n{h.payload['text']}" for h in hits)
    sys_msg = ("사용자의 코드 저장소에서 검색된 관련 조각이 아래에 주어진다. "
               "질문과 관련 있으면 이 자료를 근거로 답하고 출처 파일명을 표기하라. "
               "관련이 없으면 일반 지식으로 답하라.\n\n" + ctx)
    messages = [{"role": "system", "content": sys_msg}] + history + [{"role": "user", "content": q}]
    req = urllib.request.Request(VLLM,
        data=json.dumps({"model": "qwen3-235b", "messages": messages,
                         "max_tokens": 2000}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        ans = json.load(r)["choices"][0]["message"]["content"]
    return {"answer": ans, "sources": list({h.payload["path"] for h in hits})}
```

### `~/chat_rag.py` (camp-7, 게이트웨이 경유 대화)
```python
import json, urllib.request, urllib.error

GATEWAY = "http://192.168.0.209:9000/ask"
history = []

def sanitize(s):
    return ''.join(ch for ch in s if not (0xD800 <= ord(ch) <= 0xDFFF))

print("RAG 대화 — 235B가 저장소를 검색해서 답합니다 (여러 줄 입력 후 빈 줄로 전송, exit 종료)\n")
while True:
    print("나> (입력 후 빈 줄)")
    lines = []
    while True:
        try: line = input()
        except EOFError: line = ""
        if line == "": break
        lines.append(line)
    q = sanitize("\n".join(lines).strip())
    if not q: continue
    if q.lower() in ("exit", "quit"): break
    body = json.dumps({"question": q, "history": history[-6:]}).encode()
    req = urllib.request.Request(GATEWAY, data=body, headers={"Content-Type": "application/json"})
    print("\n[검색+생성 중...]", flush=True)
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            resp = json.load(r)
    except Exception as e:
        print(f"[에러] {e}\n"); continue
    print(f"Qwen3+RAG> {resp['answer']}\n")
    print(f"  📄 참조: {', '.join(resp['sources'])}\n")
    history += [{"role": "user", "content": q}, {"role": "assistant", "content": resp["answer"]}]
```

### camp-60 — 저장소 자동 색인 (`~/ingest.py` + cron)
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.124 'bash -s' << 'OUTER'
apt-get install -y python3-pip git >/dev/null 2>&1
pip install -q fastembed qdrant-client
mkdir -p /root/repos
cat > /root/repos.txt << 'EOF'
https://github.com/Chekoon777/EyeMovementEventDetectionAlgorithms.git eyemove
EOF
cat > /root/ingest.py << 'PYEOF'
import os, json, hashlib, uuid, subprocess
from fastembed import TextEmbedding
from qdrant_client import QdrantClient, models
QDRANT, COLL, DIM = "http://192.168.0.252:6333", "knowledge", 384
EXTS = (".py",".m",".md",".txt",".r",".cpp",".h",".ipynb",".js",".java",".ts",".sh")
STATE_F = "/root/.index_state.json"
for line in open("/root/repos.txt"):
    parts = line.split()
    if not parts: continue
    url, name = parts[0], (parts[1] if len(parts)>1 else parts[0].split("/")[-1].replace(".git",""))
    d = f"/root/repos/{name}"
    if os.path.isdir(d): subprocess.run(["git","-C",d,"pull","-q"], timeout=120)
    else: subprocess.run(["git","clone","--depth","1","-q",url,d], timeout=300)
    print(f"sync: {name}", flush=True)
state = json.load(open(STATE_F)) if os.path.exists(STATE_F) else {}
client = QdrantClient(url=QDRANT, timeout=60, check_compatibility=False)
if not client.collection_exists(COLL):
    client.create_collection(COLL, vectors_config=models.VectorParams(size=DIM, distance=models.Distance.COSINE))
def chunks(path, size=800, overlap=100):
    try: text = open(path, encoding="utf-8", errors="ignore").read()
    except: return
    for i in range(0, max(len(text),1), size-overlap):
        c = text[i:i+size].strip()
        if c: yield i, c
todo = []
for root, _, files in os.walk("/root/repos"):
    if ".git" in root: continue
    for f in files:
        if not f.endswith(EXTS): continue
        p = os.path.join(root, f)
        st = os.stat(p); sig = f"{st.st_mtime}:{st.st_size}"
        if state.get(p) != sig: todo.append((p, sig))
print(f"변경 파일: {len(todo)}개", flush=True)
if todo:
    model = TextEmbedding("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
    bt, bm, total = [], [], 0
    def flush():
        global bt, bm, total
        if not bt: return
        vecs = list(model.embed(bt)); pts = []
        for (path, off, txt), v in zip(bm, vecs):
            key = hashlib.sha256(f"{path}:{off}:{txt}".encode()).hexdigest()
            pts.append(models.PointStruct(id=str(uuid.UUID(key[:32])),
                vector=v.tolist(), payload={"path": path.replace("/root/repos/",""), "offset": off, "text": txt}))
        client.upsert(COLL, pts); total += len(pts); bt, bm = [], []
    for p, sig in todo:
        for off, c in chunks(p):
            bt.append(c); bm.append((p, off, c))
            if len(bt) >= 16: flush()
        state[p] = sig
    flush(); json.dump(state, open(STATE_F,"w"))
    print(f"색인: {total}청크 (전체 {client.count(COLL).count})", flush=True)
else: print("변경 없음", flush=True)
PYEOF
( crontab -l 2>/dev/null | grep -v ingest.py ; echo "*/10 * * * * flock -n /tmp/ingest.lock python3 -u /root/ingest.py >> /root/ingest.log 2>&1" ) | crontab -
python3 -u /root/ingest.py
OUTER
```

### camp-18 — 웹 크롤러 (`~/crawler.py`)
```bash
ssh -i ~/.ssh/ml_master root@172.10.8.185 'bash -s' << 'OUTER'
apt-get install -y python3-pip >/dev/null 2>&1
pip install -q ddgs trafilatura fastapi uvicorn
cat > /root/crawler.py << 'PYEOF'
from fastapi import FastAPI
from ddgs import DDGS
import trafilatura

app = FastAPI()

@app.post("/crawl")
def crawl(body: dict):
    q = body["question"]
    results = []
    try:
        with DDGS() as ddgs:
            hits = list(ddgs.text(q, max_results=5))
    except Exception as e:
        return {"snippets": [], "error": f"검색 실패: {e}"}
    for h in hits[:4]:
        url = h.get("href") or h.get("url")
        if not url: continue
        try:
            html = trafilatura.fetch_url(url)
            text = trafilatura.extract(html) if html else None
            if text:
                results.append({"url": url, "title": h.get("title",""), "text": text[:2000]})
        except Exception:
            continue
        if len(results) >= 3: break
    return {"snippets": results}
PYEOF
pkill -f "uvicorn crawler" 2>/dev/null; sleep 1
nohup python3 -u -m uvicorn crawler:app --host 0.0.0.0 --port 9200 --app-dir /root > /root/crawler.log 2>&1 &
sleep 6
curl -s -X POST http://localhost:9200/crawl -H "Content-Type: application/json" \
  -d '{"question": "I-VT algorithm eye movement"}' | head -c 300
echo ""
echo "크롤러 가동 확인"
OUTER
```

### 크롤러 임포트 에러 수정 (lxml_html_clean 누락)
```bash
ssh -i ~/.ssh/ml_master root@172.10.8.185 'bash -s' << 'OUTER'
pip install -q lxml_html_clean
pkill -f "uvicorn crawler" 2>/dev/null; sleep 2
nohup python3 -u -m uvicorn crawler:app --host 0.0.0.0 --port 9200 --app-dir /root > /root/crawler.log 2>&1 &
sleep 6
echo "=== 직접 호출 테스트 ==="
curl -s -X POST http://localhost:9200/crawl -H "Content-Type: application/json" \
  -d '{"question": "vLLM latest version features"}' | head -c 600
echo ""
echo "=== 로그 ==="
tail -5 /root/crawler.log
OUTER
```

### `~/gateway.py` v3 (최종 — 2단 폴백: 저장소 → 웹 크롤링)
```python
from fastembed import TextEmbedding
from qdrant_client import QdrantClient
from fastapi import FastAPI
import urllib.request, json

QDRANT  = "http://192.168.0.252:6333"
VLLM    = "http://192.168.0.228:8000/v1/chat/completions"
CRAWLER = "http://192.168.0.44:9200/crawl"
COLL, THRESH = "knowledge", 0.40

model = TextEmbedding("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
client = QdrantClient(url=QDRANT, timeout=60, check_compatibility=False)
app = FastAPI()

def ask_llm(system, history, q):
    messages = [{"role":"system","content":system}] + history + [{"role":"user","content":q}]
    req = urllib.request.Request(VLLM,
        data=json.dumps({"model":"qwen3-235b","messages":messages,"max_tokens":2000}).encode(),
        headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)["choices"][0]["message"]["content"]

@app.post("/ask")
def ask(body: dict):
    q = body["question"]
    history = body.get("history", [])
    vec = list(model.embed([q]))[0].tolist()
    hits = client.query_points(COLL, query=vec, limit=5).points
    top = hits[0].score if hits else 0.0

    if top >= THRESH:
        ctx = "\n\n---\n\n".join(f"[출처: {h.payload['path']}]\n{h.payload['text']}" for h in hits)
        sys = ("사용자 저장소에서 검색된 자료다. 이를 근거로 답하고 출처 파일명을 표기하라.\n\n" + ctx)
        return {"mode": "repo", "top_score": round(top,3),
                "answer": ask_llm(sys, history, q),
                "sources": list({h.payload["path"] for h in hits})}

    try:
        creq = urllib.request.Request(CRAWLER, data=json.dumps({"question": q}).encode(),
            headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(creq, timeout=60) as r:
            snippets = json.load(r).get("snippets", [])
    except Exception:
        snippets = []

    if snippets:
        ctx = "\n\n---\n\n".join(f"[출처: {s['url']}]\n{s['text']}" for s in snippets)
        sys = ("저장소에 관련 자료가 없어 웹에서 검색한 자료다. 이를 근거로 답하고 출처 URL을 표기하라. "
               "자료가 부족하면 부족하다고 말하라.\n\n" + ctx)
        return {"mode": "web", "top_score": round(top,3),
                "answer": ask_llm(sys, history, q),
                "sources": [s["url"] for s in snippets]}

    return {"mode": "none", "top_score": round(top,3),
            "answer": ask_llm("검색 자료 없이 일반 지식으로 답하라.", history, q), "sources": []}
```
```bash
ssh -i ~/.ssh/ml_master root@192.168.0.209 'bash -s' << 'OUTER'
pkill -f "uvicorn gateway" 2>/dev/null; sleep 2
# (위 gateway.py v3 작성)
nohup python3 -u -m uvicorn gateway:app --host 0.0.0.0 --port 9000 --app-dir /root > /root/gateway.log 2>&1 &
sleep 8
curl -s http://localhost:9000/docs >/dev/null && echo "게이트웨이 v3 가동 OK" || tail -5 /root/gateway.log
OUTER
```

### 최종 검증 — 2단 분기 테스트
```bash
curl -s http://192.168.0.209:9000/ask -H "Content-Type: application/json" \
  -d '{"question": "IVT 알고리즘의 속도 임계값은 코드에서 어떻게 쓰여?"}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('mode:',d['mode'],'| score:',d['top_score']); print(d['answer'][:300]); print('출처:',d['sources'])"
```
→ `mode: repo | score: 0.521`

```bash
curl -s http://192.168.0.209:9000/ask -H "Content-Type: application/json" \
  -d '{"question": "2026년 현재 vLLM 최신 버전의 주요 기능은?"}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('mode:',d['mode'],'| score:',d['top_score']); print(d['answer'][:300]); print('출처:',d['sources'])"
```
→ `mode: web | score: 0.368` (2단 폴백 확인)

---

## 최종 인프라 정리

| 그룹 | 서버 | 역할 |
|---|---|---|
| GPU(7) | camp-7(.228,헤드) / camp-9(.83) / camp-6(.57) / camp-8(.159) / camp-13(.123) / camp-14(.157) / camp-15(.196) | Qwen3-235B pp=7 |
| VM(Saem) | camp-57(.252) | Qdrant 벡터DB |
| | camp-58(.21) | replica (미착수) |
| | camp-59(.209) | Retrieval Gateway :9000 |
| | camp-60(.124) | 저장소 색인 (cron 10분) |
| | camp-61~69 | 임베딩 워커 (미착수) |
| | camp-70~72 | 학습데이터 파이프라인 (미착수) |
| | camp-73(.226) | 예비 |
| | camp-18(.44) | 웹 크롤러 :9200 |

핵심 스크립트 위치(camp-7): `~/vllm_env.sh`, `~/setup_nfs.sh`, `~/mount_shards.sh`, `~/chat3.py`, `~/bench3.py`, `~/chat_rag.py`
