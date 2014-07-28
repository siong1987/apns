package apns

import (
  "crypto/rsa"
  "crypto/tls"
  "crypto/x509"
  "encoding/pem"
  "errors"
  "io/ioutil"
  "log"
  "net"
  "sync"
  "time"

  "appengine"
  "appengine/socket"
)

var (
  apnsInitSync sync.Once
  notifChannel chan PushNotification
)

type APNSClient struct {
  ctx         appengine.Context
  pem         string
  passphrase  string
  apnsAddr    string            // "gateway.sandbox.push.apple.com"
  port        string            // "2195"
}

func New(ctx appengine.Context, pem string, passphrase, apnsAddr string, port string) *APNSClient {
  return &APNSClient{
    ctx:        ctx,
    pem:        pem,
    passphrase: passphrase,
    apnsAddr:   apnsAddr,
    port:       port,
  }
}

func (a *APNSClient) Send(n *PushNotification) error {
  var err error
  apnsInitSync.Do(func() {
    notifChannel = make(chan PushNotification)
    err = a.openConn()
  })
  if err != nil {
    return err
  }

  n.ctx = a.ctx
  n.finished = make(chan error)
  notifChannel <- *n

  return <-n.finished
}

func (a *APNSClient) dial() (*socket.Conn, net.Conn, error) {
  gaeConn, err := socket.Dial(a.ctx, "tcp", a.apnsAddr+ ":" + a.port)
  if err != nil {
    return nil, nil, err
  }
  certificate, err := LoadPemFile(a.pem, a.passphrase)
  if err != nil {
    return nil, nil, err
  }

  certs := []tls.Certificate{certificate}
  conf := &tls.Config{
    Certificates: certs,
  }

  apnsConn := tls.Client(gaeConn, conf)

  return gaeConn, apnsConn, nil
}

func (a *APNSClient) openConn() error {
  gaeConn, apnsConn, err := a.dial()
  if err != nil {
    return err
  }
  go func() {
    for {
      select {
      case n := <-notifChannel:
        a.ctx.Infof("Sending apns: %#v", n)
        gaeConn.SetContext(n.ctx)
        payload, err := n.ToBytes()
        n.finished <- err
	      if err != nil {
          a.ctx.Infof("APNS error parsing payload %s", err.Error())
          return
        }
        _, err = apnsConn.Write(payload)
        n.finished <- err
        if err != nil {
          a.ctx.Infof("APNS error encountered %s, reconnecting", err.Error())
          apnsConn.Close()
          gaeConn, apnsConn, err = a.dial()
          if err != nil {
            a.ctx.Infof("apns reconnect: %s", err.Error())
            return
          }
        }
        a.ctx.Infof("Finished sending apns")
      case <-time.After(time.Minute):
        log.Println("resetting apns daemon due to inactivity")
        apnsConn.Close()
        apnsInitSync = sync.Once{}
        return
      }
    }
  }()

  return nil
}

// LoadPemFile reads a combined certificate+key pem file into memory.
func LoadPemFile(pemFile string, passphrase string) (cert tls.Certificate, err error) {
  pemBlock, err := ioutil.ReadFile(pemFile)
  if err != nil {
    return
  }
  return LoadPem(pemBlock, passphrase)
}

// LoadPem is similar to tls.X509KeyPair found in tls.go except that this
// function reads all blocks from the same file.
func LoadPem(pemBlock []byte, passphrase string) (cert tls.Certificate, err error) {
  var block *pem.Block
  for {
    block, pemBlock = pem.Decode(pemBlock)
    if block == nil {
      break
    }
    if block.Type == "CERTIFICATE" {
      cert.Certificate = append(cert.Certificate, block.Bytes)
    } else {
      break
    }
  }

  ///////////////////////////////////////////////////////////////////////////
  // The rest of the code in this function is copied from the tls.X509KeyPair
  // implementation found at http://golang.org/src/pkg/crypto/tls/tls.go,
  // with the exception of minor changes (no need to decode the next block).
  ///////////////////////////////////////////////////////////////////////////

  if len(cert.Certificate) == 0 {
    err = errors.New("crypto/tls: failed to parse certificate PEM data")
    return
  }

  if block == nil {
    err = errors.New("crypto/tls: failed to parse key PEM data")
    return
  }

  var decryptedBytes []byte
  if decryptedBytes, err = x509.DecryptPEMBlock(block, []byte(passphrase)); err != nil {
    err = errors.New("crypto/tls: passphrase: " + err.Error())
    return
  }

  // OpenSSL 0.9.8 generates PKCS#1 private keys by default, while
  // OpenSSL 1.0.0 generates PKCS#8 keys. We try both.
  var key *rsa.PrivateKey
  if key, err = x509.ParsePKCS1PrivateKey(decryptedBytes); err != nil {
    var privKey interface{}
    if privKey, err = x509.ParsePKCS8PrivateKey(decryptedBytes); err != nil {
      err = errors.New("crypto/tls: failed to parse key: " + err.Error())
      return
    }

    var ok bool
    if key, ok = privKey.(*rsa.PrivateKey); !ok {
      err = errors.New("crypto/tls: found non-RSA private key in PKCS#8 wrapping")
      return
    }
  }

  cert.PrivateKey = key

  // We don't need to parse the public key for TLS, but we so do anyway
  // to check that it looks sane and matches the private key.
  x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
  if err != nil {
    return
  }

  if x509Cert.PublicKeyAlgorithm != x509.RSA || x509Cert.PublicKey.(*rsa.PublicKey).N.Cmp(key.PublicKey.N) != 0 {
    err = errors.New("crypto/tls: private key does not match public key")
    return
  }

  return
}

