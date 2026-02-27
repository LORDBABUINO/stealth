package org.backend.stealth.domain.entity;

public class Wallet {

    private Integer id;
    private String descriptor;

    public Wallet() {}

    public Wallet(Integer id, String descriptor) {
        this.id = id;
        this.descriptor = descriptor;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getDescriptor() {
        return descriptor;
    }

    public void setDescriptor(String descriptor) {
        this.descriptor = descriptor;
    }
}

