# udemy-golang-jwt

1. We will use ElephantSql service free DB

2.Create users table in DB

```sql
    create table users (
        id serial primary key,
        email text not null unique,
        password text not null
    )
```

3. Insert few users

```sql
    insert into users (email, password) values ('test@test.com', 'password')
```