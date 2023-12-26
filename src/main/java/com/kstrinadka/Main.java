package com.kstrinadka;

import java.security.Provider;
import java.security.Security;
import java.util.Set;
import java.util.TreeSet;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello world!");

        int n = ((-50) + 8) % 256;
        System.out.println(n);

        Set<String> algs = new TreeSet<>();
        for (Provider provider : Security.getProviders()) {
            provider.getServices().stream()
                    .filter(s -> "Cipher".equals(s.getType()))
                    .map(Provider.Service::getAlgorithm)
                    .forEach(algs::add);
        }
        algs.forEach(System.out::println);

    }
}