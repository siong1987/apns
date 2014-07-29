package apns

import (
  "errors"
  "sync"
  "time"
  "io"
  "net"
)

// APNSStatusCodes are codes to message from apns.
var APNSStatusCodes = map[uint8]string{
  0:   "No errors encountered",
  1:   "Processing error",
  2:   "Missing device token",
  3:   "Missing topic",
  4:   "Missing payload",
  5:   "Invalid token size",
  6:   "Invalid topic size",
  7:   "Invalid payload size",
  8:   "Invalid token",
  10:  "Shutdown",
  255: "None (unknown)",
}

var (
  apnsInitSync  sync.Once
  pool          *APNSPool
)

func (a *APNSClient) Send(n *PushNotification) error {
  var err error
  apnsInitSync.Do(func() {
    pool, err = newAPNSPool(a.Gateway, a.Pem, a.Passphrase)
  })
  if err != nil {
    return err
  }

  if n.RetryCount <= 0 {
    return errors.New("Retried more than 3 times: " + n.Error.Error())
  } else {
    n.RetryCount--
  }

  conn := pool.Get()
  defer pool.Release(conn)

  err = conn.connect(a.Ctx)
  if err != nil {
    return err
  }

  payload, err := n.ToBytes()
	if err != nil {
    a.Ctx.Infof("APNS error parsing payload %s", err.Error())
    return err
  }

  _, err = conn.TlsConn.Write(payload)
  if err != nil {
    conn.Connected = false
    n.Error = errors.New("Connection closed")
    return a.Send(n)
  }

  conn.TlsConn.SetReadDeadline(time.Now().Add(conn.ReadTimeout))
  read := [6]byte{}
  r, err := conn.TlsConn.Read(read[:])
  if err != nil {
    if err2, ok := err.(net.Error); ok && err2.Timeout() {
      // Success, apns doesn't usually return a response if successful.
      // Only issue is, is timeout length long enough (150ms) for err response.
      return nil
    }

    if err == io.EOF {
      conn.Connected = false
      n.Error = errors.New("Connection closed")
      return a.Send(n)
    }

    return err
  }

  if r >= 0 {
    status := uint8(read[1])
    switch status {
    case 0:
      return nil
    case 1, 2, 3, 4, 5, 6, 7, 8:
      //1:   "Processing error"
      //2:   "Missing Device Token",
      //3:   "Missing Topic",
      //4:   "Missing Payload",
      //5:   "Invalid Token Size",
      //6:   "Invalid Topic Size",
      //7:   "Invalid Payload Size",
      //8:   "Invalid Token",
      conn.Connected = false
      n.Error = errors.New(APNSStatusCodes[status])
      err = a.Send(n)
    default:
      conn.Connected = false
      n.Error = errors.New("Unknown error")
      err = a.Send(n)
    }
  }

  return err
}

