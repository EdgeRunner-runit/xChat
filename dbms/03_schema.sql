-- =====================================================================
-- xChat Messaging Platform - Relational Database Schema DDL (Draft)
-- Schema: xchat
-- =====================================================================

DROP SCHEMA IF EXISTS xchat CASCADE;
CREATE SCHEMA xchat;
SET search_path TO xchat;

CREATE TABLE users (
    user_id        INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username       VARCHAR(50) NOT NULL UNIQUE,
    email          VARCHAR(255) NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,
    display_name   VARCHAR(100) NOT NULL,
    avatar_url     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_presence (
    user_id            INT PRIMARY KEY REFERENCES users(user_id),
    status             VARCHAR(20) NOT NULL DEFAULT 'OFFLINE',
    custom_status_text VARCHAR(150),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspaces (
    workspace_id  INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          VARCHAR(100) NOT NULL,
    slug          VARCHAR(60) NOT NULL UNIQUE,
    owner_id      INT NOT NULL REFERENCES users(user_id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
    workspace_id  INT NOT NULL REFERENCES workspaces(workspace_id),
    user_id       INT NOT NULL REFERENCES users(user_id),
    role          VARCHAR(20) NOT NULL DEFAULT 'MEMBER',
    joined_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id),
    CONSTRAINT chk_workspace_role CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER', 'GUEST'))
);

CREATE TABLE channels (
    channel_id    INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id  INT NOT NULL REFERENCES workspaces(workspace_id),
    name          VARCHAR(80) NOT NULL,
    topic         TEXT,
    is_private    BOOLEAN NOT NULL DEFAULT false,
    created_by    INT NOT NULL REFERENCES users(user_id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE channel_members (
    channel_id             INT NOT NULL REFERENCES channels(channel_id),
    user_id                INT NOT NULL REFERENCES users(user_id),
    role                   VARCHAR(20) NOT NULL DEFAULT 'MEMBER',
    joined_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_read_message_id   INT,
    notifications_enabled  BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (channel_id, user_id),
    CONSTRAINT chk_channel_role CHECK (role IN ('ADMIN', 'MEMBER'))
);

CREATE TABLE direct_conversations (
    conversation_id  INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user1_id         INT NOT NULL REFERENCES users(user_id),
    user2_id         INT NOT NULL REFERENCES users(user_id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_canonical_users CHECK (user1_id < user2_id),
    CONSTRAINT uq_direct_participants UNIQUE (user1_id, user2_id)
);

CREATE TABLE messages (
    message_id         INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel_id         INT REFERENCES channels(channel_id),
    conversation_id    INT REFERENCES direct_conversations(conversation_id),
    sender_id          INT NOT NULL REFERENCES users(user_id),
    content            TEXT NOT NULL,
    message_type       VARCHAR(20) NOT NULL DEFAULT 'TEXT',
    is_edited          BOOLEAN NOT NULL DEFAULT false,
    is_pinned          BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attachments (
    attachment_id    INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id       INT NOT NULL REFERENCES messages(message_id),
    file_name        VARCHAR(255) NOT NULL,
    file_url         TEXT NOT NULL,
    file_size_bytes  BIGINT NOT NULL,
    mime_type        VARCHAR(100) NOT NULL,
    uploaded_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE reactions (
    message_id   INT NOT NULL REFERENCES messages(message_id),
    user_id      INT NOT NULL REFERENCES users(user_id),
    emoji_code   VARCHAR(50) NOT NULL,
    reacted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, user_id, emoji_code)
);
