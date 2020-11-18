## Setup
- ` pip install -r requirements.txt` : Installs all the requirements
- `python user_api.py` : Running the web server

## API Documentation
### Registering a new user

**Definition**

`POST /api/register`

**Sample Body**

```json
{ "username" : "testuser" ,
  "password": "helloworld",
  "confirm_password": "helloworld" ,
  "full_name" : "Test Name",
  "search_engine_name" : "Test Search Engine" }
```
**Arguments**


- `"username":string` : username of the user
- `"password":string` : password
- `"confirm_password":string` : confirm_password
- `"full_name":string` : Full_Name
- `"search_engine_name":string` : Mom's fav  search engine name

**Response**

- `201 CREATED` on success

```json
{
    "full_name": "Test Name",
    "search_engine_name": "Test Search Engine",
    "user_id": "testuser"
}
```

### Login a user

**Definition**

`POST /api/login`

**Send through Basic Auth Authorization header**

- `username` : Username used in registration
- `Password` : Password  in registration


**Response**

- `200 OK` on success

```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjA1NTkzNjkyfQ.rFhD0f6y8aCpIoTWp1vQHSNmhvrCpM-PZKmQ7gqAJ7s"
}
```

### Retrieving user details

**Definition**

`GET /api/user`


**Header**


- `"access-token": string` : Access token string from response of login


**Response**

- `200 SUCCESS` on success

```json
{
    "full_name": "Test Name",
    "search_engine_name": "Test Search Engine",
    "user_id": "testuser"
}
```

### Logging out

**Definition**

`POST /api/logout`

**Header**

- `"access-token": string` : Access token string from response of login



**Response**

- `200 OK` on success

```json
{
    "Message": "Logout Successful"
}
```
