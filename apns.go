package apns

import (
  "crypto/rsa"
  "crypto/x509"
  "crypto/tls"
  "encoding/pem"
  "io/ioutil"
  "time"
  "log"
  "errors"

  "appengine"
  "appengine/socket"
)

const (
  // maxPoolSize is the number of sockets to open per app.
  maxPoolSize = 5
)

type APNSClient struct {
  Ctx         appengine.Context
  Pem         string
  Passphrase  string
  Gateway     string
}

// APNSPool ...
type APNSPool struct {
  Pool      chan *APNSConn
}

// APNSConn ...
type APNSConn struct {
  Gateway        string
  ReadTimeout    time.Duration
  TlsConn        *tls.Conn
  TlsCfg         tls.Config
  GaeConn        *socket.Conn
  Connected      bool
}

// NewAPNSClient ...
func NewAPNSClient(ctx appengine.Context, pem string, passphrase, apnsAddr string, port string) *APNSClient {
  gateway := apnsAddr + ":" + port

  client := &APNSClient{
    Ctx:         ctx,
    Pem:         pem,
    Passphrase:  passphrase,
    Gateway:     gateway,
  }

  return client
}

// newAPNSConn is the actual connection to the remote server.
func newAPNSConn(gateway, pem, passphrase string) (*APNSConn, error) {
  conn := &APNSConn{}
  crt, err := LoadPemFile(pem, passphrase)
  if err != nil {
    return nil, err
  }
  conn.Gateway = gateway
  conn.TlsConn = nil
  conn.TlsCfg = tls.Config{
    Certificates: []tls.Certificate{crt},
  }

  conn.ReadTimeout = 150 * time.Millisecond
  conn.Connected = false

  return conn, nil
}

// newAPNSPool ...
func newAPNSPool(gateway, pem, passphrase string) (*APNSPool, error) {
  pool := make(chan *APNSConn, maxPoolSize)
  n := 0
  for x := 0; x < maxPoolSize; x++ {
    c, err := newAPNSConn(gateway, pem, passphrase)
    if err != nil {
      // Possible errors are missing/invalid environment which would be caught earlier.
      // Most likely invalid cert.
      log.Println(err)
      return nil, err
    }
    pool <- c
    n++
  }
  return &APNSPool{pool}, nil
}

// Close ...
func (c *APNSConn) Close() error {
  var err error
  if c.TlsConn != nil {
    err = c.TlsConn.Close()
    c.Connected = false
  }
  return err
}

// connect ...
func (c *APNSConn) connect(ctx appengine.Context) (err error) {
  if c.Connected {
    c.GaeConn.SetContext(ctx)
    return nil
  }

  if c.TlsConn != nil {
    c.Close()
  }

  conn, err := socket.Dial(ctx, "tcp", c.Gateway)
  if err != nil {
    log.Println(err)
    return err
  }

  c.TlsConn = tls.Client(conn, &c.TlsCfg)
  c.GaeConn = conn
  err = c.TlsConn.Handshake()
  if err == nil {
    c.Connected = true
  }

  return err
}

// Get ...
func (p *APNSPool) Get() *APNSConn {
  return <-p.Pool
}

// Release ...
func (p *APNSPool) Release(conn *APNSConn) {
  p.Pool <- conn
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

