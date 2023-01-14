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
(DEFAULT),
(DEFAULT),
(DEFAULT),
(DEFAULT),
(DEFAULT),
(DEFAULT),
(DEFAULT),
(DEFAULT),
(DEFAULT);

INSERT INTO user_data_t(
  creator_user_id,
  dateofbirth,
  username,
  realname
) VALUES
(1, 1, 'admin1', 'Admin 1'),
(2, 1, 'teacher2', 'Teacher 2'),
(3, 1, 'teacher3', 'Teacher 3'),
(4, 1, 'student4', 'Student 4'),
(5, 1, 'student5', 'Student 5'),
(6, 1, 'student6', 'Student 6'),
(7, 1, 'student7', 'Student 7'),
(8, 1, 'student8', 'Student 8'),
(9, 1, 'student9', 'Student 9');

INSERT INTO verification_challenge_t(
  verification_challenge_key_hash,
  creator_user_id,
  to_parent,
  email
) VALUES
('1', 1, FALSE, 'admin1@example.com'),
('2', 2, FALSE, 'teacher2@example.com'),
('3', 3, FALSE, 'teacher3@example.com'),
('4', 4, FALSE, 'student4@example.com'),
('5', 5, FALSE, 'student5@example.com'),
('6', 6, FALSE, 'student6@example.com'),
('7', 7, FALSE, 'student7@example.com'),
('8', 8, FALSE, 'student8@example.com'),
('9', 9, FALSE, 'student9@example.com');

INSERT INTO email_t(
  verification_challenge_key_hash
) VALUES
('1'),
('2'),
('3'),
('4'),
('5'),
('6'),
('7'),
('8'),
('9');

INSERT INTO password_t(
  creator_user_id,
  password_hash,
  password_reset_key_hash 
) VALUES
(1, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(2, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(3, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(4, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(5, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(6, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(7, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(8, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL),
(9, '$argon2i$v=19$m=4096,t=3,p=1$5adHUIBVgN/rdrCqK7vsBSS2Sz3IE/ChUVDlIExETsM$fVbg3KYf8Dd5LGBsfH5L1rTV0Xwv4C4wADmexT9uc1w', NULL);

