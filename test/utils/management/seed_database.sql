-- Seed Accounts table
INSERT INTO accounts (id, created_by, created_at, domain, domain_category, is_domain_primary_account, network_identifier, network_serial, settings_peer_login_expiration_enabled, settings_peer_login_expiration, settings_regular_users_view_blocked, settings_groups_propagation_enabled, settings_jwt_groups_enabled, settings_extra_peer_approval_enabled, network_net)
VALUES ('account1', 'user1', '2024-04-17 09:35:50.651027026+00:00', 'netbird.selfhosted', 'private', 1, 'network1', 694, 1, 86400000000000, 1, 1, 0, 0, '{"IP":"100.64.0.0","Mask":"//8AAA=="}');

-- Seed Users table
INSERT INTO users (id, account_id, role, is_service_user, non_deletable, blocked, created_at, issued)
VALUES ('user1', 'account1', 'owner', 0, 0, 0, '2024-08-12 00:00:00', 'api');

-- Seed Groups table
INSERT INTO groups (id, account_id, name, issued, peers, integration_ref_id, integration_ref_integration_type)
VALUES ('group-all', 'account1', 'All', 'api', '[]', 0, NULL);

-- Seed Personal Access Tokens (API Keys) table
INSERT INTO personal_access_tokens (id, user_id, name, hashed_token, expiration_date, created_by, created_at, last_used)
VALUES ('1', 'user1', 'Test API Key', 'smJvzexPcQ3NRezrVDUmF++0XqvFvXzx8Rsn2y9r1z0=', '2124-08-12 00:00:00', 'user1', '2024-08-12 00:00:00', NULL);
