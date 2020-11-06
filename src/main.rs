#[macro_use]
extern crate diesel;

pub mod models;
pub mod schema;

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use dotenv::dotenv;
use tera::{Context, Tera};

use argonautica::Verifier;

use crate::models::{
    Comment, CommentForm, LoginUser, NewComment, NewPost, NewUser, Post, PostForm, User,
};

type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Debug)]
enum ServerError {
    ArgonauticError,
    DieselError,
    EnvironmentError,
    R2D2Error,
    TeraError,
    UserError(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Test")
    }
}

impl actix_web::error::ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServerError::ArgonauticError => {
                HttpResponse::InternalServerError().json("Argonautica Error")
            }
            ServerError::DieselError => HttpResponse::InternalServerError().json("Diesel Error"),
            ServerError::EnvironmentError => {
                HttpResponse::InternalServerError().json("Envrionment Error")
            }
            ServerError::R2D2Error => HttpResponse::InternalServerError().json("R2D2 Error"),
            ServerError::TeraError => HttpResponse::InternalServerError().json("Tera Error"),
            ServerError::UserError(data) => HttpResponse::InternalServerError().json(data),
        }
    }
}

impl From<std::env::VarError> for ServerError {
    fn from(err: std::env::VarError) -> ServerError {
        log::error!("{:?}", err);
        ServerError::EnvironmentError
    }
}

impl From<r2d2::Error> for ServerError {
    fn from(err: r2d2::Error) -> ServerError {
        log::error!("{:?}", err);
        ServerError::R2D2Error
    }
}

impl From<argonautica::Error> for ServerError {
    fn from(err: argonautica::Error) -> ServerError {
        log::error!("{:?}", err);
        ServerError::ArgonauticError
    }
}

impl From<diesel::result::Error> for ServerError {
    fn from(err: diesel::result::Error) -> ServerError {
        log::error!("{:?}", err);
        match err {
            diesel::result::Error::NotFound => {
                ServerError::UserError("Username not found".to_owned())
            }
            _ => ServerError::DieselError,
        }
    }
}

impl From<tera::Error> for ServerError {
    fn from(err: tera::Error) -> ServerError {
        log::error!("{:?}", err);
        ServerError::TeraError
    }
}

async fn index(tera: web::Data<Tera>, pool: web::Data<Pool>) -> Result<HttpResponse, ServerError> {
    use crate::schema::posts::dsl::posts;
    use crate::schema::users::dsl::users;

    let connection = pool.get()?;
    let all_posts: Vec<(Post, User)> = posts.inner_join(users).load(&connection)?;

    let mut data = Context::new();
    data.insert("title", "Hacker Clone");
    data.insert("posts_users", &all_posts);

    let rendered = tera.render("index.html", &data)?;
    Ok(HttpResponse::Ok().body(rendered))
}

async fn signup(tera: web::Data<Tera>) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Sign Up");

    let rendered = tera.render("signup.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn process_signup(
    data: web::Form<NewUser>,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServerError> {
    use crate::schema::users;

    let connection = pool.get()?;
    let new_user = NewUser::new(
        data.username.clone(),
        data.email.clone(),
        data.password.clone(),
    );

    diesel::insert_into(users::table)
        .values(&new_user)
        .get_result::<User>(&connection)?;

    println!("{:?}", data);
    Ok(HttpResponse::Ok().body(format!("Successfully saved user: {}", data.username)))
}

async fn login(tera: web::Data<Tera>, id: Identity) -> Result<HttpResponse, ServerError> {
    let mut data = Context::new();
    data.insert("title", "Login");

    if let Some(_id) = id.identity() {
        return Ok(HttpResponse::Ok().body("Already logged in"));
    }

    let rendered = tera.render("login.html", &data)?;
    Ok(HttpResponse::Ok().body(rendered))
}

async fn process_login(
    data: web::Form<LoginUser>,
    pool: web::Data<Pool>,
    id: Identity,
) -> Result<HttpResponse, ServerError> {
    use crate::schema::users::dsl::{username, users};

    let connection = pool.get()?;
    let user = users
        .filter(username.eq(&data.username))
        .first::<User>(&connection)?;

    dotenv().ok();

    let secret = std::env::var("SECRET_KEY")?;

    let valid = Verifier::default()
        .with_hash(user.password)
        .with_password(data.password.clone())
        .with_secret_key(secret)
        .verify()?;

    if valid {
        let session_token = String::from(user.username);
        id.remember(session_token);
        Ok(HttpResponse::Ok().body(format!("Loggen in: {}", data.username)))
    } else {
        Ok(HttpResponse::Ok().body("Password is incorrect"))
    }
}

async fn logout(id: Identity) -> impl Responder {
    id.forget();
    HttpResponse::Ok().body("Logged out")
}

async fn submission(tera: web::Data<Tera>, id: Identity) -> Result<HttpResponse, ServerError> {
    let mut data = Context::new();
    data.insert("title", "Submission");

    if let Some(_id) = id.identity() {
        let rendered = tera.render("submission.html", &data)?;
        return Ok(HttpResponse::Ok().body(rendered));
    }

    Ok(HttpResponse::Unauthorized().body("User not logged in"))
}

async fn process_submission(
    data: web::Form<PostForm>,
    pool: web::Data<Pool>,
    id: Identity,
) -> Result<HttpResponse, ServerError> {
    if let Some(id) = id.identity() {
        use crate::schema::users::dsl::{username, users};

        let connection = pool.get()?;
        let user: Result<User, diesel::result::Error> =
            users.filter(username.eq(id)).first(&connection);

        match user {
            Ok(user) => {
                let new_post =
                    NewPost::from_post_form(data.title.clone(), data.link.clone(), user.id);

                use crate::schema::posts;

                diesel::insert_into(posts::table)
                    .values(&new_post)
                    .get_result::<Post>(&connection)?;

                return Ok(HttpResponse::Ok().body("Submitted"));
            }
            Err(e) => {
                println!("{:?}", e);
                return Ok(HttpResponse::Ok().body("Failed to find user"));
            }
        }
    }

    Ok(HttpResponse::Unauthorized().body("User not logged in"))
}

async fn post_page(
    tera: web::Data<Tera>,
    pool: web::Data<Pool>,
    web::Path(post_id): web::Path<i32>,
    id: Identity,
) -> Result<HttpResponse, ServerError> {
    use crate::schema::posts::dsl::posts;
    use crate::schema::users::dsl::users;

    let connection = pool.get()?;
    let post: Post = posts.find(post_id).get_result(&connection)?;
    let user: User = users.find(post.author).get_result(&connection)?;
    let comments: Vec<(Comment, User)> = Comment::belonging_to(&post)
        .inner_join(users)
        .load(&connection)?;

    let mut data = Context::new();
    data.insert("title", &format!("{} - Hacker Clone", post.title));
    data.insert("post", &post);
    data.insert("user", &user);
    data.insert("comments", &comments);

    if let Some(_id) = id.identity() {
        data.insert("logged_in", "true");
    } else {
        data.insert("logged_in", "false");
    }

    let rendered = tera.render("post.html", &data)?;
    Ok(HttpResponse::Ok().body(rendered))
}

async fn comment(
    data: web::Form<CommentForm>,
    pool: web::Data<Pool>,
    web::Path(post_id): web::Path<i32>,
    id: Identity,
) -> Result<HttpResponse, ServerError> {
    if let Some(id) = id.identity() {
        use crate::schema::comments;
        use crate::schema::posts::dsl::posts;
        use crate::schema::users::dsl::{username, users};

        let connection = pool.get()?;
        let post: Post = posts.find(post_id).get_result(&connection)?;
        let user: Result<User, diesel::result::Error> =
            users.filter(username.eq(id)).first(&connection);

        match user {
            Ok(user) => {
                let parent_id: Option<i32> = None;
                let new_comment =
                    NewComment::new(data.comment.clone(), post.id, user.id, parent_id);

                diesel::insert_into(comments::table)
                    .values(&new_comment)
                    .get_result::<Comment>(&connection)?;

                return Ok(HttpResponse::Ok().body("Commented"));
            }
            Err(e) => {
                println!("{:?}", e);
                return Ok(HttpResponse::NotFound().body("User not found"));
            }
        }
    }

    Ok(HttpResponse::Unauthorized().body("Not logged in"))
}

async fn user_profile(
    tera: web::Data<Tera>,
    pool: web::Data<Pool>,
    web::Path(requested_user): web::Path<String>,
) -> Result<HttpResponse, ServerError> {
    use crate::schema::users::dsl::{username, users};

    let connection = pool.get()?;
    let user: User = users
        .filter(username.eq(requested_user))
        .get_result(&connection)?;
    let posts: Vec<Post> = Post::belonging_to(&user).load(&connection)?;
    let comments: Vec<Comment> = Comment::belonging_to(&user).load(&connection)?;

    let mut data = Context::new();
    data.insert("title", &format!("{} - Profile", user.username));
    data.insert("user", &user);
    data.insert("posts", &posts);
    data.insert("comments", &comments);

    let rendered = tera.render("profile.html", &data)?;
    Ok(HttpResponse::Ok().body(rendered))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    HttpServer::new(move || {
        dotenv().ok();

        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let manager = ConnectionManager::<PgConnection>::new(db_url);
        let pool = r2d2::Pool::builder()
            .build(manager)
            .expect("Failed to create postgres pool");

        let tera = match Tera::new("templates/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };

        App::new()
            .wrap(Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .secure(false),
            ))
            .data(tera)
            .data(pool)
            .route("/", web::get().to(index))
            .route("/signup", web::get().to(signup))
            .route("/signup", web::post().to(process_signup))
            .route("/login", web::get().to(login))
            .route("/login", web::post().to(process_login))
            .route("/logout", web::to(logout))
            .route("/submission", web::get().to(submission))
            .route("/submission", web::post().to(process_submission))
            .service(
                web::resource("/post/{post_id}")
                    .route(web::get().to(post_page))
                    .route(web::post().to(comment)),
            )
            .service(web::resource("/user/{username}").route(web::get().to(user_profile)))
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
