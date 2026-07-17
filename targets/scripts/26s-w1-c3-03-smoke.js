const { io } = require("socket.io-client");

const BASE_URL = process.env.P2_TARGET_URL || "http://127.0.0.1:3000";

function waitFor(socket, eventName, predicate = () => true, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.off(eventName, onEvent);
      reject(new Error(`timed out waiting for ${eventName}`));
    }, timeoutMs);

    function onEvent(payload) {
      try {
        if (!predicate(payload)) return;
        clearTimeout(timer);
        socket.off(eventName, onEvent);
        resolve(payload);
      } catch (error) {
        clearTimeout(timer);
        socket.off(eventName, onEvent);
        reject(error);
      }
    }

    socket.on(eventName, onEvent);
  });
}

function connectPlayer(label) {
  return new Promise((resolve, reject) => {
    const socket = io(BASE_URL, {
      transports: ["websocket"],
      timeout: 5000,
      forceNew: true,
      reconnection: false
    });
    const timer = setTimeout(() => reject(new Error(`${label} connect timeout`)), 5000);
    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("connect_error", reject);
  });
}

async function main() {
  const root = await fetch(`${BASE_URL}/`);
  if (root.status !== 200) {
    throw new Error(`root returned ${root.status}`);
  }

  const host = await connectPlayer("host");
  const guest = await connectPlayer("guest");

  try {
    const hostRoomUpdate = waitFor(
      host,
      "room_update",
      (payload) => payload?.players?.some((player) => player.userId === "p2-host")
    );
    host.emit("create_room", {
      roomName: "P2 Local Room",
      level: 1,
      maxPlayers: 2,
      userId: "p2-host",
      nickname: "P2Host",
      point: 0,
      profileImage: "profile.png"
    });
    const created = await hostRoomUpdate;
    if (!created.roomCode || created.players.length !== 1 || created.phase !== "WAITING") {
      throw new Error(`unexpected created room payload: ${JSON.stringify(created)}`);
    }

    const validation = await new Promise((resolve) => {
      guest.emit("validate_join_room", { roomCode: created.roomCode, privateCode: "" }, resolve);
    });
    if (!validation?.ok) {
      throw new Error(`join validation failed: ${JSON.stringify(validation)}`);
    }

    const joinedUpdate = waitFor(
      host,
      "room_update",
      (payload) => payload?.roomCode === created.roomCode && payload.players?.length === 2
    );
    guest.emit("join_room", {
      roomCode: created.roomCode,
      privateCode: "",
      userId: "p2-guest",
      nickname: "P2Guest",
      point: 0,
      profileImage: "profile.png"
    });
    const joined = await joinedUpdate;
    if (!joined.players.some((player) => player.userId === "p2-guest")) {
      throw new Error(`guest missing from room update: ${JSON.stringify(joined)}`);
    }

    const readyUpdate = waitFor(
      host,
      "room_update",
      (payload) => payload?.roomCode === created.roomCode && payload.players?.some((player) => player.userId === "p2-guest" && player.isReady)
    );
    guest.emit("toggle_ready", { roomCode: created.roomCode });
    await readyUpdate;
  } finally {
    host.disconnect();
    guest.disconnect();
  }
}

main().then(() => {
  console.log("26s-w1-c3-03 socket smoke passed");
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
