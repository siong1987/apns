# APNS on Google App Engine

A simple library to send APNS on Google App Engine.

## Example

```go
client := apns.New(c, "secret.pem", "passphrase", "gateway.sandbox.push.apple.com", "2195")
aps := apns.APS{
  Alert: "Hello world!",
}

payload := apns.Payload{
  APS: aps,
}

notification := apns.Notification{
  Device:     "device_token",
  Payload:    payload,
  Expiration: time.Now().Add(time.Hour),
	Lazy:       false,
}

client.Send(notification)
```

## Thanks

* [https://github.com/pkar/hermes](https://github.com/pkar/hermes)
* [https://github.com/anachronistic/apns](https://github.com/anachronistic/apns)
