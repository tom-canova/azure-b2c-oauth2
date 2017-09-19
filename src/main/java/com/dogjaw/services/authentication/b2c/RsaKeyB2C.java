package com.dogjaw.services.authentication.b2c;

import java.util.Base64;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by Keith Hoopes on 2/25/2016.
 */
public class RsaKeyB2C {

    @JsonProperty("kid")
    private String kid;

    @JsonProperty("use")
    private String use;

    @JsonProperty("kty")
    private String kty;

    @JsonProperty("e")
    private String e;

    @JsonProperty("n")
    private String n;

    @JsonProperty("nbf")
    private long nbf;
    
    public long getNbf() {
    	return nbf;
    }
    
    public void setNbf(long nbf) {
    	this.nbf = nbf;
    }
    
    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getE() {
        return e;
    }

    public void setE(String e) {
        this.e = e;
    }
    
    public byte[] getEDecoded() {
        return Base64.getUrlDecoder().decode(this.e);
    }

    public String getN() {
        return n;
    }

    public void setN(String n) {
        this.n = n;
    }
    
    public byte[] getNDecoded() {
        return Base64.getUrlDecoder().decode(this.n);
    }
}
