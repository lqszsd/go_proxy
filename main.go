package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/elazarl/goproxy"
	"io/ioutil"
	"log"
	"net/http"
)
/**
生成本地证书 用golang自带crypto
go run $GOROOT/src/crypto/tls/generate_cert.go --host localhost
 */
func main() {
	proxy := goproxy.NewProxyHttpServer()
	caCert, _ := ioutil.ReadFile("cert.pem") // 设置为你刚才生成的 ca.pem 路径
	caKey, _ := ioutil.ReadFile("key.pem")  // 设置为你刚才生成的 ca.key.pem 路径
	setCA(caCert, caKey)
	proxy.Verbose = true
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnResponse().DoFunc(
		func(r *http.Response,ctx *goproxy.ProxyCtx)(*http.Response) {
			fmt.Println("这是拿到返回的请求",ctx.Req.URL.String())
			buf := new(bytes.Buffer)
			buf.ReadFrom(r.Body)
			r.Body = ioutil.NopCloser(bytes.NewBuffer(buf.Bytes()))
			if ctx.Req.URL.String()=="http://fms.glerp.cn:805/reports/index.php?c=iostore_document_export&m=download_file&id=424&file_index=0"{
				ioutil.WriteFile("test.xlsx",buf.Bytes(),0777)
			}
			//fmt.Println("拿到https返回值",string(buf.Bytes()))
			return r
		})
	proxy.OnRequest().DoFunc(
		func(r *http.Request,ctx *goproxy.ProxyCtx)(*http.Request,*http.Response) {
			fmt.Println("打印host",r.Host,r.URL)
			if r.Host=="www.baidus.com"{
				return r,goproxy.NewResponse(r,
					goproxy.ContentTypeText,http.StatusForbidden,
					"Don't waste your time!")
			}
			return r,nil
		})
	log.Fatal(http.ListenAndServe(":8080", proxy))
}


func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}