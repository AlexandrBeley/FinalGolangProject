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
    //"os"
    "github.com/golang-jwt/jwt/v5"
)

type GetInf struct {
    User        string
    ID          int
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

var TimePlus, TimeMinus, TimeMult, TimeDivis time.Duration
var Information []Info
var ch []GetInf
var mu sync.Mutex

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
    id := len(Information)
    Information = append(Information, Info{st, user_name, TimePlus, TimeMinus, TimeMult, TimeDivis, id, 0, 0, fmt.Errorf("200")})
    //value, timeProcess, err := 
    fmt.Fprintln(w, id, user_name, len(Information))
    //go CountProcess(&Information[id])
    ch = append(ch, GetInf{user_name, id})
    mu.Unlock()
 }
func UserTokenHandler(w http.ResponseWriter, r *http.Request) {
    stUser := r.URL.Query().Get("user")
    token, err := CreateToken(stUser)
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
    fmt.Fprintf(w, "ID: %d\nValue: %f\nCode: %s\nProcessTime: %s\nString: %s", id, info_.Value, info_.Error, info_.ProcessTime, info_.CountStr)
    
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
        fmt.Fprintf(w, "ID: %d Value: %f Code: %s ProcessTime: %s String: %s\n", Information[i].ID, Information[i].Value, Information[i].Error, Information[i].ProcessTime,Information[i].CountStr)
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

func main() {
    //CreateToken()
	
    TimePlus = time.Second
    TimeMinus = time.Second
    TimeDivis = time.Second
    TimeMult = time.Second
    /*file_path := "C:\\Users\\aleks\\codeing\\go\\code\\ЯндексЛицей\\2\\финальная_задача\\data.txt"
    _, err := os.ReadFile(file_path)
    if err != nil {
        fmt.Println(err)
    } else {
        fmt.Println("ok")
    }*/
    Information = make([]Info, 0)
    ch = make([]GetInf, 0)

	mux := http.NewServeMux()

	main_ := http.HandlerFunc(MainHandler)
    time_ := http.HandlerFunc(TimeHandler)
    info_ := http.HandlerFunc(InfoHandler)
    data_ := http.HandlerFunc(DataHandler)
    token_ := http.HandlerFunc(UserTokenHandler)
    
	mux.Handle("/", Meine(main_))
    mux.Handle("/times/", Meine(time_))
    mux.Handle("/get/", Meine(info_))
    mux.Handle("/data/", Meine(data_))
    mux.Handle("/token/", Meine(token_))

    go func(){
        for {
            mu.Lock()
            if len(ch) > 0 {
                a := ch[0].ID
                b := ch[0].User
                info_, err := GetInfo(b, a)
                if err != nil {
                    fmt.Println("not find")
                } else {
                    fmt.Println(b, a)
                    go CountProcessNew(info_)
                }
                /*
                for i := 0; i < len(Information); i += 1 {
                    if Information[i].UserName == b && Information[i].ID == a {
                        go CountProcessNew(&Information[a])
                        break
                    }
                }*/
                ch = ch[1:]
            }
            mu.Unlock()
            time.Sleep(time.Millisecond * 200)
        }
    }()
    fmt.Println("start ok")
	http.ListenAndServe(":" + ipStr, mux)
}
func CreateToken(user string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": user, //inf.UserName, //"user_name",
		"nbf":  now.Unix(),
		"exp":  now.Add(10 * time.Minute).Unix(),
		"iat":  now.Unix(),
	})

	tokenString, err := token.SignedString([]byte(hmacSampleSecret))
	if err != nil {
		return "", err
	}

	//fmt.Println("token string:", tokenString)
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
func CountProcessNew(inf *Info) (float64, time.Duration, error){
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
    if st == "\/" {
        return inf.TimeDivis, true
    }
    return time.Second, false
 }
/*
    go run "C:\Users\aleks\codeing\go\code\ЯндексЛицей\final_task_main\cmd\server\main01.go"
*/