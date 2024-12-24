package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.common.entities.Token;
import org.example.yogabusinessmanagementweb.common.entities.User;

import java.util.List;

public interface TokenService {

    List<Token> getAllTokensByUserName(String userName);
}
