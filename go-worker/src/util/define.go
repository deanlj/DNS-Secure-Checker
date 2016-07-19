package util

type RequestMessage struct{
  Domain string `json:"domain"`
  ID  string `json:"id"`
  Type string `json:"type"`
}

type ResonseMessage  struct{
  Message string `json:"message"`
  Error string `json:"error"`
  Type string `json:"type"`
}
