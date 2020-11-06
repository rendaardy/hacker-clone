CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR NOT NULL,
  email VARCHAR NOT NULL,
  password VARCHAR NOT NULL,

  UNIQUE(username),
  UNIQUE(email)
);

CREATE TABLE posts (
  id SERIAL PRIMARY KEY,
  title VARCHAR NOT NULL,
  link VARCHAR,
  author INT NOT NULL,
  created_at TIMESTAMP NOT NULL,

  CONSTRAINT fk_author
  FOREIGN KEY(author)
  REFERENCES users(id)
);

CREATE TABLE comments (
  id SERIAL PRIMARY KEY,
  comment VARCHAR NOT NULL,
  post_id INT NOT NULL,
  user_id INT NOT NULL,
  parent_comment_id INT,
  created_at TIMESTAMP NOT NULL,

  CONSTRAINT fk_post
  FOREIGN KEY(post_id)
  REFERENCES posts(id),

  CONSTRAINT fk_user
  FOREIGN KEY(user_id)
  REFERENCES users(id),

  CONSTRAINT fk_parent_comment
  FOREIGN KEY(parent_comment_id)
  REFERENCES comments(id)
)