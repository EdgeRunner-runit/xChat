# xChat Database Normalization: 1NF → 2NF → 3NF → BCNF

**Application:** xChat (Enterprise Real-Time Messaging Platform)  
**Author:** Kushal Garg (`kshlgrg`) · **Enrollment No.:** 2501010241  
**Course:** Advanced Programming (AP) / Database Management Systems (DBMS)  
**Deliverable:** Checkpoint 1 (CP1) — Normalization Document  

---

## 1. Domain Context & Unnormalized Representation (UNF)

**xChat** manages enterprise communication across workspaces, channels, direct messages, attachments, and reactions. Initially, an unnormalized logging record or NoSQL document captures an entire channel interaction in a single flat structure.

### 1.1 Unnormalized Relation (UNF)
```text
UNF_CHAT_DATA (
    workspace_id, workspace_name, workspace_slug, workspace_owner_id, workspace_owner_name,
    workspace_members [ { member_id, member_name, member_email, role, joined_at } ],
    channel_id, channel_name, channel_topic, is_private, channel_creator_id, channel_creator_name,
    channel_members [ { user_id, user_name, user_role, last_read_message_id } ],
    message_id, parent_message_id, sender_id, sender_username, sender_email,
    content, message_type, is_edited, is_pinned, message_created_at,
    attachments [ { attachment_id, file_name, file_url, file_size, mime_type } ],
    reactions [ { emoji_code, reacted_by_user_id, reacted_by_username, reacted_at } ]
)
```

### 1.2 Anomalies in UNF:
* **Insertion Anomaly:** A new user cannot exist without being part of a workspace message; a workspace cannot be created without sending a message.
* **Deletion Anomaly:** Deleting a message deletes attachment metadata, user profile data, and channel details.
* **Update Anomaly:** Updating a user's display name or email requires scanning and modifying thousands of historical message records.

---

## 2. First Normal Form (1NF)

### 2.1 Rule of 1NF
A relation is in 1NF if and only if:
1. Every attribute value is **atomic** (indivisible scalar).
2. There are no repeating groups, arrays, or nested records.
3. A primary key uniquely identifies each tuple.

### 2.2 Decomposition to 1NF
We unnest the repeating arrays (`workspace_members`, `channel_members`, `attachments`, `reactions`) and represent every domain as scalar attributes:

```text
1. TABLE_USERS_1NF (
       user_id, username, email, password_hash, display_name, avatar_url, 
       presence_status, custom_status, created_at, last_seen_at
   )
   Primary Key: {user_id}

2. TABLE_WORKSPACES_1NF (
       workspace_id, name, slug, owner_id, created_at
   )
   Primary Key: {workspace_id}

3. TABLE_WORKSPACE_MEMBERS_1NF (
       workspace_id, user_id, role, joined_at
   )
   Primary Key: {workspace_id, user_id}

4. TABLE_CHANNELS_1NF (
       channel_id, workspace_id, name, topic, is_private, created_by, created_at
   )
   Primary Key: {channel_id}

5. TABLE_CHANNEL_MEMBERS_1NF (
       channel_id, user_id, role, joined_at, last_read_message_id, notifications_enabled
   )
   Primary Key: {channel_id, user_id}

6. TABLE_DIRECT_CONVERSATIONS_1NF (
       conversation_id, user1_id, user2_id, created_at
   )
   Primary Key: {conversation_id}

7. TABLE_MESSAGES_1NF (
       message_id, channel_id, conversation_id, sender_id, parent_message_id,
       content, message_type, is_edited, is_pinned, created_at, updated_at
   )
   Primary Key: {message_id}

8. TABLE_ATTACHMENTS_1NF (
       attachment_id, message_id, file_name, file_url, file_size_bytes, mime_type, uploaded_at
   )
   Primary Key: {attachment_id}

9. TABLE_REACTIONS_1NF (
       message_id, user_id, emoji_code, reacted_at
   )
   Primary Key: {message_id, user_id, emoji_code}
```

### 2.3 Functional Dependencies at 1NF:
* $FD_1: \text{user\_id} \rightarrow \text{username}, \text{email}, \text{password\_hash}, \text{display\_name}, \text{avatar\_url}, \text{presence\_status}, \text{created\_at}$
* $FD_2: \text{username} \rightarrow \text{user\_id}, \text{email}, \dots$
* $FD_3: \text{email} \rightarrow \text{user\_id}, \text{username}, \dots$
* $FD_4: \text{workspace\_id} \rightarrow \text{name}, \text{slug}, \text{owner\_id}, \text{created\_at}$
* $FD_5: \{\text{workspace\_id}, \text{user\_id}\} \rightarrow \text{role}, \text{joined\_at}$
* $FD_6: \text{channel\_id} \rightarrow \text{workspace\_id}, \text{name}, \text{topic}, \text{is\_private}, \text{created\_by}, \text{created\_at}$
* $FD_7: \{\text{channel\_id}, \text{user\_id}\} \rightarrow \text{role}, \text{joined\_at}, \text{last\_read\_message\_id}, \text{notifications\_enabled}$
* $FD_8: \text{conversation\_id} \rightarrow \text{user1\_id}, \text{user2\_id}, \text{created\_at}$
* $FD_9: \{\text{user1\_id}, \text{user2\_id}\} \rightarrow \text{conversation\_id}, \text{created\_at}$
* $FD_{10}: \text{message\_id} \rightarrow \text{channel\_id}, \text{conversation\_id}, \text{sender\_id}, \text{parent\_message\_id}, \text{content}, \text{message\_type}, \text{created\_at}$
* $FD_{11}: \text{attachment\_id} \rightarrow \text{message\_id}, \text{file\_name}, \text{file\_url}, \text{file\_size\_bytes}, \text{mime\_type}, \text{uploaded\_at}$
* $FD_{12}: \{\text{message\_id}, \text{user\_id}, \text{emoji\_code}\} \rightarrow \text{reacted\_at}$

---

## 3. Second Normal Form (2NF)

### 3.1 Rule of 2NF
A relation is in 2NF if and only if:
1. It is in **1NF**.
2. There are **no partial dependencies**: no non-prime attribute is functionally dependent on a proper subset of any candidate key.

### 3.2 Evaluation of Composite Key Relations:
1. **`TABLE_WORKSPACE_MEMBERS_1NF`:**
   - Candidate Key: $\{\text{workspace\_id}, \text{user\_id}\}$
   - Non-prime attributes: $\{\text{role}, \text{joined\_at}\}$
   - Dependence: Neither $\text{workspace\_id} \rightarrow \text{role}$ nor $\text{user\_id} \rightarrow \text{role}$ holds. Both attributes depend fully on the complete composite key. $\rightarrow$ **Satisfies 2NF.**
2. **`TABLE_CHANNEL_MEMBERS_1NF`:**
   - Candidate Key: $\{\text{channel\_id}, \text{user\_id}\}$
   - Non-prime attributes: $\{\text{role}, \text{joined\_at}, \text{last\_read\_message\_id}, \text{notifications\_enabled}\}$
   - Fully dependent on $\{\text{channel\_id}, \text{user\_id}\}$. $\rightarrow$ **Satisfies 2NF.**
3. **`TABLE_REACTIONS_1NF`:**
   - Candidate Key: $\{\text{message\_id}, \text{user\_id}, \text{emoji\_code}\}$
   - Non-prime attribute: $\text{reacted\_at}$
   - A user reacting with an emoji at a given time requires all three attributes to identify the reaction event. $\rightarrow$ **Satisfies 2NF.**
4. **All Single-Attribute Key Relations (`users`, `workspaces`, `channels`, `messages`, `attachments`, `direct_conversations`):**
   - Because their primary keys consist of a single attribute, partial key dependencies are mathematically impossible. $\rightarrow$ **Satisfies 2NF.**

---

## 4. Third Normal Form (3NF)

### 4.1 Rule of 3NF
A relation is in 3NF if and only if:
1. It is in **2NF**.
2. There are **no transitive dependencies**: for every non-trivial functional dependency $X \rightarrow Y$, either:
   - $X$ is a **superkey**, OR
   - $Y$ is a **prime attribute** (part of a candidate key).

### 4.2 Transitive Dependency Identification & Decomposition:
In `TABLE_USERS_1NF`, presence state and status text (`presence_status`, `custom_status`, `status_updated_at`) change frequently in real time (every few seconds), whereas user authentication profiles change rarely.
* In high-throughput architectures, retaining volatile presence in the user authentication table creates unnecessary write locks and cache invalidation.
* We decouple live presence into a dedicated 1:1 relation: `user_presence`.

**Transitive Dependency Check on Channels & Workspaces:**
* In `channels`, does $\text{channel\_id} \rightarrow \text{created\_by} \rightarrow \text{creator\_email}$ exist?
  - Since creator email and details are stored strictly in `users`, `channels` contains *only* the foreign key $\text{created\_by}$. No transitive attributes exist.
* In `messages`, sender metadata is resolved through foreign key $\text{sender\_id}$. No sender names or emails are stored redundantly.

### 4.3 3NF Relation Definitions:
1. **`users`** $(\underline{\text{user\_id}}, \text{username}, \text{email}, \text{password\_hash}, \text{display\_name}, \text{avatar\_url}, \text{created\_at}, \text{last\_seen\_at})$
2. **`user_presence`** $(\underline{\text{user\_id}}, \text{status}, \text{custom_status_text}, \text{updated_at})$
3. **`workspaces`** $(\underline{\text{workspace\_id}}, \text{name}, \text{slug}, \text{owner\_id}, \text{created\_at})$
4. **`workspace_members`** $(\underline{\text{workspace\_id}, \text{user\_id}}, \text{role}, \text{joined\_at})$
5. **`channels`** $(\underline{\text{channel\_id}}, \text{workspace\_id}, \text{name}, \text{topic}, \text{is\_private}, \text{created\_by}, \text{created\_at})$
6. **`channel_members`** $(\underline{\text{channel\_id}, \text{user\_id}}, \text{role}, \text{joined\_at}, \text{last\_read\_message\_id}, \text{notifications\_enabled})$
7. **`direct_conversations`** $(\underline{\text{conversation\_id}}, \text{user1\_id}, \text{user2\_id}, \text{created\_at})$
8. **`messages`** $(\underline{\text{message\_id}}, \text{channel\_id}, \text{conversation\_id}, \text{sender\_id}, \text{parent\_message\_id}, \text{content}, \text{message\_type}, \text{is\_edited}, \text{is\_pinned}, \text{created\_at}, \text{updated\_at})$
9. **`attachments`** $(\underline{\text{attachment\_id}}, \text{message\_id}, \text{file\_name}, \text{file\_url}, \text{file\_size\_bytes}, \text{mime\_type}, \text{uploaded\_at})$
10. **`reactions`** $(\underline{\text{message\_id}, \text{user\_id}, \text{emoji\_code}}, \text{reacted\_at})$

---

## 5. Boyce-Codd Normal Form (BCNF)

### 5.1 Rule of BCNF
A relation is in BCNF if and only if for every non-trivial functional dependency $X \rightarrow Y$, **$X$ is a superkey**. (BCNF eliminates anomalies where a determinant is a prime attribute but not a candidate key).

### 5.2 Verification Across All 10 Tables:

| Table | Candidate Keys | Functional Dependencies ($X \rightarrow Y$) | Is $X$ a Superkey? | BCNF Status |
|---|---|---|:---:|:---:|
| **`users`** | $\{\text{user\_id}\}, \{\text{username}\}, \{\text{email}\}$ | $\text{user\_id} \rightarrow \text{All}$<br>$\text{username} \rightarrow \text{All}$<br>$\text{email} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`user_presence`** | $\{\text{user\_id}\}$ | $\text{user\_id} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`workspaces`** | $\{\text{workspace\_id}\}, \{\text{slug}\}$ | $\text{workspace\_id} \rightarrow \text{All}$<br>$\text{slug} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`workspace_members`** | $\{\text{workspace\_id}, \text{user\_id}\}$ | $\{\text{workspace\_id}, \text{user\_id}\} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`channels`** | $\{\text{channel\_id}\}, \{\text{workspace\_id}, \text{name}\}$ | $\text{channel\_id} \rightarrow \text{All}$<br>$\{\text{workspace\_id}, \text{name}\} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`channel_members`** | $\{\text{channel\_id}, \text{user\_id}\}$ | $\{\text{channel\_id}, \text{user\_id}\} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`direct_conversations`** | $\{\text{conversation\_id}\}, \{\text{user1\_id}, \text{user2\_id}\}$ | $\text{conversation\_id} \rightarrow \text{All}$<br>$\{\text{user1\_id}, \text{user2\_id}\} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`messages`** | $\{\text{message\_id}\}$ | $\text{message\_id} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`attachments`** | $\{\text{attachment\_id}\}$ | $\text{attachment\_id} \rightarrow \text{All}$ | Yes | **Satisfies BCNF** |
| **`reactions`** | $\{\text{message\_id}, \text{user\_id}, \text{emoji\_code}\}$ | $\{\text{message\_id}, \text{user\_id}, \text{emoji\_code}\} \rightarrow \text{reacted\_at}$ | Yes | **Satisfies BCNF** |

### 5.3 BCNF Canonical Analysis on `direct_conversations`:
In direct messaging, a conversation between User $A$ and User $B$ must be identical to a conversation between User $B$ and User $A$.
* If permitted without ordering, both $(A, B)$ and $(B, A)$ could be inserted, causing duplicate conversation threads.
* We enforce canonical ordering at the database level:
  `CONSTRAINT chk_canonical_users CHECK (user1_id < user2_id)`
  and `UNIQUE (user1_id, user2_id)`.
* Consequently, $\{\text{user1\_id}, \text{user2\_id}\}$ is a deterministic candidate key. Every determinant is a superkey. **Satisfies BCNF.**

---

## 6. Conclusion
The xChat schema is mathematically verified to satisfy **1NF, 2NF, 3NF, and BCNF**. It completely eliminates update, deletion, and insertion anomalies, and provides a sound relational foundation for production PostgreSQL deployment.
