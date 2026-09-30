# Data model

## User

One record for each account.

- id: unique identifier
- username: unique name used to sign in
- passwordHash: securely stored password hash
- displayName: name shown on the site
- bio: optional profile text
- photoUrl: optional profile picture URL
- isGuest: whether this is a guest account
- createdAt: account creation time

## Follow

One record for a request from one user to follow another.

- id: unique identifier
- followerId: user who sent the request
- followingId: user receiving the request
- status: PENDING or ACCEPTED
- createdAt: request creation time

A followerId and followingId pair must be unique. A user cannot follow themselves. Declining a request removes its record.

## Post

One record for each post.

- id: unique identifier
- authorId: user who wrote it
- content: post text
- imageUrl: optional image URL for extra credit
- createdAt: post creation time

## Like

One record for one user's like on one post.

- id: unique identifier
- userId: user who liked the post
- postId: post that was liked

A userId and postId pair must be unique.

## Comment

One record for each comment on a post.

- id: unique identifier
- authorId: user who wrote the comment
- postId: post receiving the comment
- content: comment text
- createdAt: comment creation time

## Relationships and feed rule

- One User can write many Posts and Comments.
- One Post can have many Comments and Likes.
- Follow connects two Users.
- Like connects a User and a Post.
- The home feed shows recent Posts by the signed-in User and by Users they follow through ACCEPTED Follow records.
