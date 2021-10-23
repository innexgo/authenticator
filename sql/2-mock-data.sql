-- users:
-- user: alpha@example.com 
-- pass: Boolean500

-- user: beta@example.com 
-- pass: Boolean500

-- user: gamma@example.com 
-- pass: Boolean500

\c auth

INSERT INTO user_t(
  creation_time
) VALUES
(1),
(1),
(1),
(1),
(1),
(1),
(1),
(1),
(1);

INSERT INTO user_data_t(
  creation_time,
  creator_user_id,
  name
) VALUES
(1, 1, 'Admin 1'),
(1, 2, 'Teacher 2'),
(1, 3, 'Teacher 3'),
(1, 4, 'Student 4'),
(1, 5, 'Student 5'),
(1, 6, 'Student 6'),
(1, 7, 'Student 7'),
(1, 8, 'Student 8'),
(1, 9, 'Student 9');

INSERT INTO verification_challenge_t(
  verification_challenge_key_hash,
  creation_time,
  creator_user_id,
  to_parent,
  email
) VALUES
('1', 1, 1, FALSE, 'admin1@example.com'),
('2', 1, 2, FALSE, 'teacher2@example.com'),
('3', 1, 3, FALSE, 'teacher3@example.com'),
('4', 1, 4, FALSE, 'student4@example.com'),
('5', 1, 5, FALSE, 'student5@example.com'),
('6', 1, 6, FALSE, 'student6@example.com'),
('7', 1, 7, FALSE, 'student7@example.com'),
('8', 1, 8, FALSE, 'student8@example.com'),
('9', 1, 9, FALSE, 'student9@example.com');

INSERT INTO email_t(
  creation_time,
  creator_user_id,
  verification_challenge_key_hash
) VALUES
(1, 1, '1'),
(1, 2, '2'),
(1, 3, '3'),
(1, 4, '4'),
(1, 5, '5'),
(1, 6, '6'),
(1, 7, '7'),
(1, 8, '8'),
(1, 9, '9');

INSERT INTO parent_permission_t(
  creation_time,
  user_id,
  verification_challenge_key_hash
) VALUES
(1, 1, NULL),
(1, 2, NULL),
(1, 3, NULL),
(1, 4, NULL),
(1, 5, NULL),
(1, 6, NULL),
(1, 7, NULL),
(1, 8, NULL),
(1, 9, NULL);

INSERT INTO password_t(
  creation_time,
  creator_user_id,
  password_hash,
  password_reset_key_hash 
) VALUES
(1, 1, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(1, 2, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(1, 3, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(1, 4, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(1, 5, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(1, 6, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(1, 7, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(1, 8, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(1, 9, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL);

\c innexgo_hours


