package main

import (
    "fmt"
    "time"
    "strconv"
	"net/http"
    "strings"
	"sync"
	"go/token"
	"go/types"
    "github.com/golang-jwt/jwt/v5"
	"context"
	"database/sql"
    "log"

    _ "github.com/mattn/go-sqlite3"
)

type GetInf struct {
    UserName    string
    ID          int
}
type User struct {
    ID          int64
    UserName    string
    Password    string
}
type Info struct {
    CountStr    string
    UserName    string
    TimePlus    time.Duration
    TimeMinus   time.Duration
    TimeMult    time.Duration
    TimeDivis   time.Duration
    ID          int
    ProcessTime time.Duration
    Value       float64
    Error       error
}

const hmacSampleSecret = "SuPeR-SeCrEt-SiGnAtUrE"
const ipStr = "1229"
const dbPath = "C:/storefs.db"

var TimePlus, TimeMinus, TimeMult, TimeDivis time.Duration
var Information []Info
var ch []GetInf
var mu sync.Mutex
var db *sql.DB
var Ctx context.Context

func (u User) Print() string {
	id := strconv.FormatInt(u.ID, 10)
	return "ID: " + id + " \tName: " + u.UserName + " \tPassword: " + u.Password
 }
func (i Info) Print() string {
    return fmt.Sprintf("ID: %d \tUser: %s \tValue: %d \tCode: %s \tProcessTime: %s \tString: %s", i.ID, i.UserName, int(i.Value), i.Error, i.ProcessTime, i.CountStr)
 }
func MainHandler(w http.ResponseWriter, r *http.Request) {
    st := r.URL.Query().Get("nm")
    st = strings.ReplaceAll(st, string(rune(32)), "+")
    user_name, err := UserFromToken(r.URL.Query().Get("token"))
    if err != nil {
        fmt.Fprintln(w, err)
        return
    }
    fmt.Fprintln(w, st)

    mu.Lock()
    id, err := insertExpression(Ctx, db, &Info{st, user_name, TimePlus, TimeMinus, TimeMult, TimeDivis, 0, 0, 0, fmt.Errorf("200")})
    if err != nil {
        fmt.Fprintln(w, err)
        return
    }
    Information = append(Information, Info{st, user_name, TimePlus, TimeMinus, TimeMult, TimeDivis, int(id), 0, 0, fmt.Errorf("200")})
    fmt.Fprintln(w, id, user_name)
    ch = append(ch, GetInf{user_name, int(id)})
    mu.Unlock()
 }
func UserTokenHandler(w http.ResponseWriter, r *http.Request) {
    stUser := r.URL.Query().Get("user")
    stPassword := r.URL.Query().Get("password")
    user, err := selectUserByName(Ctx, db, stUser)
    if fmt.Sprint(err) == "sql: no rows in result set" {
        fmt.Fprintf(w, "Неверное имя пользователя")
        return
    }
    if err != nil {
        fmt.Fprintln(w, err)
        return
    }
    if user.Password == stPassword {
        token, err := CreateToken(stUser)
        if err != nil {
            fmt.Fprintln(w, err)
            return  
        }
        fmt.Fprintf(w, "Токен для пользователя %s:\n%s", stUser, token)
        return
    }
    fmt.Fprintf(w, "Неверный пароль")
 }
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
    stUser := r.URL.Query().Get("user")
    stPassword := r.URL.Query().Get("password")
    if _, err := selectUserByName(Ctx, db, stUser); err == nil {
        fmt.Fprintln(w, "Пользователь существует", stUser, stPassword)
        return
    }
    token, err := CreateToken(stUser)
    if err != nil {
        fmt.Fprintln(w, err)
        return  
    }
    _, err = insertUser(Ctx, db, &User{0, stUser, stPassword})
    if err != nil {
        fmt.Fprintln(w, err)
        return
    }
    fmt.Fprintf(w, "Токен для пользователя %s:\n%s", stUser, token)
 }
func TimeHandler(w http.ResponseWriter, r *http.Request) {
    sleepDurPlus, errPlus := time.ParseDuration(r.URL.Query().Get("timePlus"))    //time.Millisecond * 1100
    sleepDurMinus, errMinus := time.ParseDuration(r.URL.Query().Get("timeMinus")) 
    sleepDurMult, errMult := time.ParseDuration(r.URL.Query().Get("timeMult")) 
    sleepDurDivis, errDivis := time.ParseDuration(r.URL.Query().Get("timeDivis")) 
    if errPlus != nil {
        fmt.Fprintln(w, errPlus)
    } else {
        TimePlus = sleepDurPlus
    }
    if errMinus != nil {
        fmt.Fprintln(w, errMinus)
    } else {
        TimeMinus = sleepDurMinus
    }
    if errDivis != nil {
        fmt.Fprintln(w, errDivis)
    } else {
        TimeDivis = sleepDurDivis
    }
    if errMult != nil {
        fmt.Fprintln(w, errMult)
    } else {
        TimeMult = sleepDurMult
    }
    fmt.Fprintln(w, "Время сложения:", TimePlus)
    fmt.Fprintln(w, "Время вычитания:", TimeMinus)
    fmt.Fprintln(w, "Время деления:", TimeDivis)
    fmt.Fprintln(w, "Время умножения:", TimeMult)
 }
func InfoHandler(w http.ResponseWriter, r *http.Request) {
    user_name, err := UserFromToken(r.URL.Query().Get("token"))
    if err != nil {
        fmt.Fprintln(w, err)
        return
    }
    id, err := strconv.Atoi(r.URL.Query().Get("id"))
    if err != nil {
        fmt.Fprintln(w, fmt.Errorf("Некорректный ID"))
        return
    } 
    info_, err := GetInfo(user_name, id)
    if err != nil {
        fmt.Fprintln(w, fmt.Errorf("Неправильный токен или ID"))
        return
    } 
    fmt.Fprintf(w, "ID: %d\nValue: %d\nCode: %s\nProcessTime: %s\nString: %s", id, int(info_.Value), info_.Error, info_.ProcessTime, info_.CountStr)
    
 }
func DataHandler(w http.ResponseWriter, r *http.Request) {
    user_name, err := UserFromToken(r.URL.Query().Get("token"))
    if err != nil {
        fmt.Fprintln(w, err)
        return
    }
    for i := range Information {
        if Information[i].UserName != user_name {
            continue
        }
        mu.Lock()
        fmt.Fprintln(w, Information[i].Print())
        mu.Unlock()
    }  
    mu.Lock()
    fmt.Fprintln(w,ch)
    mu.Unlock()
 }

func Meine(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
 }
func chUpdate() error {
    ch = make([]GetInf, 0)
    ch_, err := selectExpressionsByError(Ctx, db, fmt.Errorf("200"))
	if err != nil {
		panic(err)
        return err
	}
    for i := range ch_ {
		ch = append(ch, GetInf{ch_[i].UserName, ch_[i].ID})
	}
    return nil
}
func insertUser(ctx_ context.Context, db_ *sql.DB, user *User) (int64, error) {
	var q = `
	INSERT INTO users (name, password) values ($1, $2)
	`
	result, err := db_.ExecContext(ctx_, q, user.UserName, user.Password)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return id, nil
 }
func selectUsers(ctx context.Context, db *sql.DB) ([]User, error) {
	var users []User
	var q = "SELECT id, name, password FROM users"
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		u := User{}
		err := rows.Scan(&u.ID, &u.UserName, &u.Password)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, nil
 }
func selectUserByName(ctx context.Context, db *sql.DB, name string) (User, error) {
	u := User{}
	var q = "SELECT id, name, password FROM users WHERE name = $1"
	err := db.QueryRowContext(ctx, q, name).Scan(&u.ID, &u.UserName, &u.Password)
	if err != nil {
		return u, err
	}

	return u, nil
 }
func selectExpressions(ctx context.Context, db *sql.DB) ([]Info, error) {
	var expressions []Info
	var q = "SELECT id, expression, username, value, error, processtime FROM expressions"

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		e := Info{}
        var err_, time_ string
		err := rows.Scan(&e.ID, &e.CountStr, &e.UserName, &e.Value, &err_, &time_)
		if err != nil {
			return nil, err
		}
        e.ProcessTime, err = time.ParseDuration(time_) 
        if err != nil {
            return nil, err
        }
        e.Error = fmt.Errorf(err_)
		expressions = append(expressions, e)
	}

	return expressions, nil
 }
func selectExpressionsByID(ctx context.Context, db *sql.DB, ID int) (Info, error) {
	var q = "SELECT expression, value, username, error, processtime FROM expressions WHERE id = $1"

	e := Info{}
    var err_, time_ string
    err := db.QueryRowContext(ctx, q, ID).Scan(&e.CountStr, &e.Value, &e.UserName, &err_, &time_)
	if err != nil {
		return e, err
	}
    e.ProcessTime, err = time.ParseDuration(time_) 
    if err != nil {
        return e, err
    }
    e.Error = fmt.Errorf(err_)
    e.ID = ID

	return e, nil
}
func selectExpressionsByError(ctx context.Context, db *sql.DB, Error error) ([]Info, error) {
	var expressions []Info
	var q = "SELECT id, username FROM expressions WHERE error = $1"

    rows, err := db.QueryContext(ctx, q, fmt.Sprint(Error))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		e := Info{}
		err := rows.Scan(&e.ID,&e.UserName)
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, e)
	}

	return expressions, nil
}
func insertExpression(ctx_ context.Context, db_ *sql.DB, inf *Info) (int64, error) {
	var q = `
	INSERT INTO expressions (expression, username, value, error, processtime) values ($1, $2, $3, $4, $5)
	`
	result, err := db_.ExecContext(ctx_, q, inf.CountStr, inf.UserName, inf.Value, fmt.Sprint(inf.Error), fmt.Sprint(inf.ProcessTime))
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return id, nil
 }
func updateExpression(ctx context.Context, db_ *sql.DB, inf *Info) error {
    var q = `
	UPDATE expressions SET value = $1, error = $2, processtime = $3 WHERE id = $4
	`
	_, err := db_.ExecContext(ctx, q, inf.Value, fmt.Sprint(inf.Error), fmt.Sprint(inf.ProcessTime), inf.ID)
	if err != nil {
		return err
	}

	return nil
}
func createTables(ctx context.Context, db *sql.DB) error {
	const (
		usersTable = `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT, 
		name TEXT NOT NULL,
		password TEXT NOT NULL
	);`
        expressionsTable = `
	CREATE TABLE IF NOT EXISTS expressions(
		id INTEGER PRIMARY KEY AUTOINCREMENT, 
		expression TEXT NOT NULL,
		username TEXT NOT NULL,
        value INTEGER,
        error TEXT,
        processtime TEXT
	);`
	)

	if _, err := db.ExecContext(ctx, usersTable); err != nil {
		return err
	}

    if _, err := db.ExecContext(ctx, expressionsTable); err != nil {
		return err
	}

	return nil
 }
func main() {
	Ctx = context.TODO()
    var err error
	db, err = sql.Open("sqlite3", "C:/dataBse/storefs.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.PingContext(Ctx)
	if err != nil {
		panic(err)
	}

	if err = createTables(Ctx, db); err != nil {
		panic(err)
	}

	Users, err := selectUsers(Ctx, db)
	if err != nil {
		panic(err)
	}
    for i := range Users {
		log.Println(Users[i].Print())
	}
    Information, err = selectExpressions(Ctx, db)
	if err != nil {
		panic(err)
	}
    for i := range Information {
		log.Println(Information[i].Print())
	}

    chUpdate()

    TimePlus = time.Second
    TimeMinus = time.Second
    TimeDivis = time.Second
    TimeMult = time.Second
    

	mux := http.NewServeMux()

	main_ := http.HandlerFunc(MainHandler)
    time_ := http.HandlerFunc(TimeHandler)
    info_ := http.HandlerFunc(InfoHandler)
    data_ := http.HandlerFunc(DataHandler)
    token_ := http.HandlerFunc(UserTokenHandler)
    reg_ := http.HandlerFunc(RegisterHandler)
    
	mux.Handle("/", Meine(main_))
    mux.Handle("/times/", Meine(time_))
    mux.Handle("/get/", Meine(info_))
    mux.Handle("/data/", Meine(data_))
    mux.Handle("/login/", Meine(token_))
    mux.Handle("/register/", Meine(reg_))

    go func(){
        for {
            mu.Lock()
            if len(ch) > 0 {
                a := ch[0].ID
                b := ch[0].UserName
                info_, err := GetInfo(b, a)
                if err != nil {
                    fmt.Println("not find")
                } else {
                    go func() {
                        CountProcess(info_)
                        err = updateExpression(Ctx, db, info_)
                        if err != nil {
                            panic(err)
                        }
                    }()
                }
                ch = ch[1:]
            }
            mu.Unlock()
            time.Sleep(time.Millisecond * 200)
        }
    }()
    go func(){
        for {
            mu.Lock()
            chUpdate()
            mu.Unlock()
            time.Sleep(time.Second * 4)
        }
    }()
    fmt.Println("start ok")
	http.ListenAndServe(":" + ipStr, mux)
}
func CreateToken(user string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": user, 
		"nbf":  now.Unix(),
		"exp":  now.Add(10 * time.Minute).Unix(),
		"iat":  now.Unix(),
	})
	tokenString, err := token.SignedString([]byte(hmacSampleSecret))
	if err != nil {
		return "", err
	}

    return tokenString, nil
 }
func UserFromToken(tokenString string) (string, error) {
    tokenFromString, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			panic(fmt.Errorf("unexpected signing method: %v", token.Header["alg"]))
		}
		return []byte(hmacSampleSecret), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := tokenFromString.Claims.(jwt.MapClaims); ok {
		return fmt.Sprint(claims["name"]), nil
	} 
    return "", err
 }
func GetInfo(user string, ID int) (*Info, error) {
    for i := range Information {
        if Information[i].UserName == user && Information[i].ID == ID {
            return &Information[i], nil
        }
    }
    return nil, fmt.Errorf("not find")
 }
func CountProcess(inf *Info) (float64, time.Duration, error){
    expression := inf.CountStr
    createTime := time.Now()
	calcTime := createTime
	for i := 0; i < len(expression); i++ {
		if v, ok := GetTime(string(expression[i]), inf); ok {
			calcTime = calcTime.Add(time.Duration(v))
		}
	}
    time.Sleep(calcTime.Sub(createTime))
    fs := token.NewFileSet()
    tv, err := types.Eval(fs, nil, token.NoPos, inf.CountStr)
    if err != nil {
        inf.Value = 0
        inf.Error = fmt.Errorf("400")
        return 0,0,inf.Error
    } 
    inf.Value, _ = strconv.ParseFloat(tv.Value.String(), 64)
    inf.Error = nil
    inf.ProcessTime = calcTime.Sub(createTime)
    
    return inf.Value, inf.ProcessTime, nil
 }
func GetTime(st string, inf *Info) (time.Duration, bool) {
    if st == "+" {
        return inf.TimePlus, true
    }
    if st == "-" {
        return inf.TimeMinus, true
    }
    if st == "*" {
        return inf.TimeMult, true
    }
    if st == "/" {
        return inf.TimeDivis, true
    }
    return time.Second, false
 }
