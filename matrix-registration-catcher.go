package main

import (
        "context"
        "encoding/json"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "strings"
        "time"

        "gopkg.in/yaml.v3"
        "maunium.net/go/mautrix"
        "maunium.net/go/mautrix/event"
        "maunium.net/go/mautrix/id"
)

type Config struct {
        MatrixServer string `yaml:"MatrixServer"`
        Username     string `yaml:"Username"`
        Password     string `yaml:"Password"`
        LogRoom      string `yaml:"LogRoom"`
        ListenPort   int    `yaml:"ListenPort"`
}

type TokenFile struct {
        UserID      string    `json:"user_id"`
        AccessToken string    `json:"access_token"`
        Timestamp   time.Time `json:"timestamp"`
}

const tokenFilePath = "matrix_token.json"

var (
        cfg    Config
        client *mautrix.Client
        roomID id.RoomID
)

func loadConfig() error {
        data, err := ioutil.ReadFile("config.yaml")
        if err != nil {
                return err
        }
        return yaml.Unmarshal(data, &cfg)
}

func saveTokenFile(userID, accessToken string) error {
        token := TokenFile{
                UserID:      userID,
                AccessToken: accessToken,
                Timestamp:   time.Now(),
        }
        data, err := json.MarshalIndent(token, "", "  ")
        if err != nil {
                return err
        }
        return ioutil.WriteFile(tokenFilePath, data, 0600)
}

func loadTokenFile() (*TokenFile, error) {
        data, err := ioutil.ReadFile(tokenFilePath)
        if err != nil {
                return nil, err
        }
        var token TokenFile
        if err := json.Unmarshal(data, &token); err != nil {
                return nil, err
        }
        return &token, nil
}

func isTokenValid(server, userID, accessToken string) bool {
        c, err := mautrix.NewClient(server, id.UserID(userID), accessToken)
        if err != nil {
                return false
        }
        _, err = c.Whoami(context.Background())
        return err == nil
}

func initMatrix() error {
        var err error
        client, err = mautrix.NewClient(cfg.MatrixServer, "", "")
        if err != nil {
                return fmt.Errorf("failed to create matrix client: %w", err)
        }

        // 1. Try to use stored token
        if token, err := loadTokenFile(); err == nil {
                if isTokenValid(cfg.MatrixServer, token.UserID, token.AccessToken) {
                        client.SetCredentials(id.UserID(token.UserID), token.AccessToken)
                        roomID = id.RoomID(cfg.LogRoom)
                        fmt.Println("Using cached Matrix token.")
                        return nil
                } else {
                        fmt.Println("Cached Matrix token invalid, will login again.")
                }
        }

        // 2. Login and cache token
        resp, err := client.Login(
                context.Background(),
                &mautrix.ReqLogin{
                        Type: "m.login.password",
                        Identifier: mautrix.UserIdentifier{
                                Type: mautrix.IdentifierTypeUser,
                                User: cfg.Username,
                        },
                        Password: cfg.Password,
                },
        )
        if err != nil {
                return fmt.Errorf("matrix login failed: %w", err)
        }
        client.SetCredentials(resp.UserID, resp.AccessToken)
        roomID = id.RoomID(cfg.LogRoom)
        if err := saveTokenFile(string(resp.UserID), resp.AccessToken); err != nil {
                log.Printf("Warning: could not save token file: %v", err)
        }
        fmt.Println("Matrix login successful, token cached.")
        return nil
}

func getSourceIP(r *http.Request) string {
        xff := r.Header.Get("X-Forwarded-For")
        if xff != "" {
                // Take first value if multiple IPs present
                return strings.Split(xff, ",")[0]
        }
        return r.RemoteAddr
}

func matrixLog(sourceIP, method, body, userAgent string) {
        plainMsg := fmt.Sprintf(
                "Register endpoint called\n\n"+
                        "SourceIP: %s\n"+
                        "method: %s\n"+
                        "user-agent: %s\n"+
                        "body: %s",
                sourceIP, method, userAgent, body,
        )
        htmlMsg := fmt.Sprintf(
                "<b>Register endpoint called</b><br><br>"+
                        "<b>SourceIP</b>: <code>%s</code><br>"+
                        "<b>method</b>: <code>%s</code><br>"+
                        "<b>user-agent</b>: <code>%s</code><br>"+
                        "<b>body</b>: <code>%s</code>",
                sourceIP, method, userAgent, body,
        )

        // Print to console (plain)
        fmt.Println(plainMsg)

        // Send to Matrix (HTML)
        if client == nil {
                fmt.Println("MAUTRIX not initialized, would log:", plainMsg)
                return
        }
        _, err := client.SendMessageEvent(
                context.Background(),
                roomID,
                event.EventMessage,
                &event.MessageEventContent{
                        MsgType:       event.MsgText,
                        Body:          plainMsg,
                        Format:        event.FormatHTML,
                        FormattedBody: htmlMsg,
                },
        )
        if err != nil {
                log.Printf("Failed to log to matrix: %v", err)
        }
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
        // CORS headers
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
        if r.Method == http.MethodOptions {
                w.WriteHeader(http.StatusOK)
                return
        }

        bodyBytes, _ := ioutil.ReadAll(r.Body)
        r.Body.Close()
        clientIP := getSourceIP(r)
        body := string(bodyBytes)
        userAgent := r.Header.Get("User-Agent")
        matrixLog(clientIP, r.Method, body, userAgent)

        resp := map[string]interface{}{
                "session": "register_session_id",
                "flows": []map[string]interface{}{
                        {"stages": []string{"m.login.dummy"}},
                },
                "params": map[string]interface{}{},
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func main() {
        if err := loadConfig(); err != nil {
                fmt.Printf("Failed to load config.yaml: %v\n", err)
                os.Exit(1)
        }
        if err := initMatrix(); err != nil {
                fmt.Printf("Matrix init failed: %v\n", err)
                client = nil
        }

        http.HandleFunc("/_matrix/client/v3/register", registerHandler)
        addr := fmt.Sprintf(":%d", cfg.ListenPort)
        fmt.Printf("Listening on %s\n", addr)
        log.Fatal(http.ListenAndServe(addr, nil))
}
