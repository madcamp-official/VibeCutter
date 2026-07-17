"""Endpoint ↔ Role ↔ Source Symbol ↔ Data Store ↔ UI Action 통합 그래프 (7.1절).

Day1 완료 기준("타깃 1 endpoint ↔ role graph")의 산출물이자, 3.2절 핵심 가설
("도구 결과를 LLM에 단순 전달하는 방식보다 endpoint-role-code graph를 유지하는 방식이
Broken Access Control 탐지에 유리하다")의 실체.

7.1절 예시:
    UI: Delete Post button
      → DELETE /api/posts/{postId}
      → PostController.delete() → PostService.deletePost() → PostRepository.deleteById()
      → Required policy: requester == owner OR role == ADMIN
"""
