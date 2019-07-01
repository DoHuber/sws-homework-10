create table users
(
    id INTEGER
        constraint users_pk
            primary key autoincrement,
    username VARCHAR(50),
    password VARCHAR(50),
    signed_up DATE,
    privileges VARCHAR(50)
);

