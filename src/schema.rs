table! {
    comments (id) {
        id -> Int4,
        comment -> Varchar,
        post_id -> Int4,
        user_id -> Int4,
        parent_comment_id -> Nullable<Int4>,
        created_at -> Timestamp,
    }
}

table! {
    posts (id) {
        id -> Int4,
        title -> Varchar,
        link -> Nullable<Varchar>,
        author -> Int4,
        created_at -> Timestamp,
    }
}

table! {
    users (id) {
        id -> Int4,
        username -> Varchar,
        email -> Varchar,
        password -> Varchar,
    }
}

joinable!(comments -> posts (post_id));
joinable!(comments -> users (user_id));
joinable!(posts -> users (author));

allow_tables_to_appear_in_same_query!(comments, posts, users,);
