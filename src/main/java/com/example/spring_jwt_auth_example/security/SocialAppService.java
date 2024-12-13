package com.example.spring_jwt_auth_example.security;

import com.example.spring_jwt_auth_example.entity.RoleType;
import com.example.spring_jwt_auth_example.entity.User;
import com.example.spring_jwt_auth_example.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@AllArgsConstructor
public class SocialAppService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // Extract user attributes
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");

        // Check if user exists in the repository
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setUsername((String) attributes.get("name"));
            newUser.setRoles(Set.of(RoleType.ROLE_USER));
            return userRepository.save(newUser);
        });

        // Return the OAuth2User with authorities
        return new DefaultOAuth2User(
                user.getRoles().stream()
                        .map(r -> new SimpleGrantedAuthority(r.name()))
                        .collect(Collectors.toSet()),
                attributes,
                "name");
    }
}
