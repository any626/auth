package main

import (
    "fmt"
    "log"
    "net/http"
    "github.com/dgrijalva/jwt-go"
    "encoding/json"
    "time"
    "strings"
    "github.com/gorilla/mux"
    "github.com/urfave/negroni"

    "database/sql"
    _ "github.com/lib/pq"
    "./config"
    "./models"
    "golang.org/x/crypto/bcrypt"
)


type Env struct {
    db *models.DB
}

type Login struct {
    Email string
    Password string
}

type Token struct {
    Token string `json:"token"`
}

func main() {

    // to change the flags on the default logger
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    config := config.GetConfig("./config/config.json")

    db, err := models.NewDB(config)

    if err != nil {
        log.Fatal(err)
    }

    env := &Env{db: db}

    router := mux.NewRouter()
    router.HandleFunc("/", indexHandler)
    router.HandleFunc("/login", env.loginHandler).Methods("POST")
    router.HandleFunc("/register", env.registerHandler).Methods("POST")

    authRoutes := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
    authRoutes.HandleFunc("/auth", authHandler)

    n := negroni.Classic()

    router.PathPrefix("/api/v1").Handler(negroni.New(
        negroni.HandlerFunc(jsonMiddleware),
        negroni.HandlerFunc(authMiddleware),
        negroni.Wrap(authRoutes),
    ))

    n.UseHandler(router)
    log.Fatal(http.ListenAndServe(":8080", n))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    fmt.Fprintln(w, r.Form)
}

func (env *Env) registerHandler(w http.ResponseWriter, r *http.Request) {
    decoder := json.NewDecoder(r.Body)
    register := struct {
        Email string `json:"email"`
        EmailConfirm string `json:"email_confirm"`
        Password string `json:"password"`
        PasswordConfirm string `json:"password_confirm"`
    }{}
    err := decoder.Decode(&register)
    if err != nil {
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusBadRequest) ,http.StatusBadRequest)
        return
    }

    if (register.Email != register.EmailConfirm || register.Password != register.PasswordConfirm || register.Email == "" || register.Password == "") {
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
        return
    }

    exists, err := env.db.UserExists(register.Email)
    if err != nil{
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
        return
    }
    if exists {
        http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
        return
    }

    bcryptPassword, err := bcrypt.GenerateFromPassword([]byte(register.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
        return
    }

    password := sql.NullString{String: string(bcryptPassword), Valid:true}

    newUser := models.User{Email: register.Email, Password: password, CreatedAt: time.Now(), UpdatedAt: time.Now()}
    err = env.db.CreateUser(&newUser)
    if err != nil{
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
        return
    }

    return
}

func (env *Env) loginHandler(w http.ResponseWriter, r *http.Request) {
    decoder := json.NewDecoder(r.Body)
    var login Login
    err := decoder.Decode(&login)
    if err != nil {
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusBadRequest) ,http.StatusBadRequest)
        return
    }

    // validate
    if (login.Email == "" || login.Password == "") {
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
        return
    }

    user, err := env.db.GetUserByEmail(login.Email)

    if err != nil {
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusUnprocessableEntity) ,http.StatusUnprocessableEntity)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.Password.String), []byte(login.Password))
    if err != nil {
        log.Println(err)
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    mySigningKey := []byte("AllYourBase")

    expiresAt := time.Now().Add(time.Hour * 24).Unix()
    // Create the Claims
    claims := &jwt.StandardClaims{
        ExpiresAt: expiresAt,
        Issuer:    "test",
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    ss, err := token.SignedString(mySigningKey)
    if err != nil {
        fmt.Println(err)
        http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
        return
    }

    signedToken := Token{Token:ss}
    // fmt.Fprintf(w, "%v %v", ss, err)
    
    js, err := json.Marshal(signedToken)
    if err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write(js)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, `{"status": "success"}`)
}

func authMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
    // Get token from the Authorization header
    // format: Authorization: Bearer 
    tokenString := r.Header.Get("Authorization")
    tokenString = strings.TrimPrefix(tokenString, "Bearer ")

    // If the tokenString is empty...
    if tokenString == "" {
        // If we get here, the required token is missing
        jsonError(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    // Parse takes the token string and a function for looking up the key. The latter is especially
    // useful if you use multiple keys for your application.  The standard is to use 'kid' in the
    // head of the token to identify which key to use, but the parsed token (head and claims) is provided
    // to the callback, providing flexibility.
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Don't forget to validate the alg is what you expect:
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
        }

        // hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
        return []byte("AllYourBase"), nil
    })

    if err != nil {
        jsonError(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        fmt.Println(claims)
    } else {
        jsonError(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    next(w, r)
    // do some stuff after
}

func jsonMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
    w.Header().Set("Content-Type", "application/json")
    next(w,r)
}

func jsonError(w http.ResponseWriter, statusText string, status int) {
    w.WriteHeader(status)
    fmt.Fprintf(w, `{"error":%q}`, statusText)
}