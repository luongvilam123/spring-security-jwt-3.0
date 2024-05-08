package com.example.security.service;

import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * This class is used to retrieve user-related data,
 * load details about the user during authentication.
 */

@Service
@RequiredArgsConstructor
public class UserDetailsImp implements UserDetailsService {

    final private UserRepository userRepository;

    /**
     * @param email the client username
     * @return the user information related to log in
     * @throws UsernameNotFoundException exception
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findUserByEmail(email).orElseThrow(()-> new UsernameNotFoundException(email));
    }

}
