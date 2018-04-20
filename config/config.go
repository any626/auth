package config

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
)

type Config struct {
    Host string `json:"host"`
    Port int `json:"port"`
    Database string `json:"database"`
    Username string `json:"username"`
    Password string `json:"password"`
    Sslmode string `json:"sslmode"`
}

func GetConfig(filePath string) Config {
    raw, err := ioutil.ReadFile(filePath)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    var c Config
    json.Unmarshal(raw, &c)
    return c
}

