-- P2 local-only smoke fixture. It is mounted into a fresh Compose volume only.
-- The IDs are deliberately non-production fixtures and no Roblox API is called.
INSERT INTO users (user_id, username, display_name)
VALUES (900000001, 'p2-local-user', 'P2 Local User');

INSERT INTO games (
    universe_id, place_id, name, description, genre_l1, genre_l2,
    playing, visits, favorited_count, created, up_votes, down_votes,
    creator_type, creator_group_id, minimum_age, icon_url, fan_cacheable, updated_at
)
VALUES (
    900000101, 900000201, 'P2 Fixture Game', 'Local-only fixture for tier-save validation.', 'Adventure', 'Puzzle',
    10, 100, 5, '2025-01-01 00:00:00', 8, 1,
    'User', NULL, 0, NULL, FALSE, CURRENT_TIMESTAMP
);
