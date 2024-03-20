package mx.edu.utez.sda.jwtjbp.service;

import mx.edu.utez.sda.jwtjbp.entity.UserInfo;
import mx.edu.utez.sda.jwtjbp.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserInfoService implements UserDetailsService {
    @Autowired
    private UserInfoRepository userInfoRepository;
    @Autowired
    private PasswordEncoder passwordEncoder; 

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserInfo> userDetail = userInfoRepository.findByUsername(username);
        return userDetail.map(UserInfoDetails::new)
                .orElseThrow(
                        () -> new UsernameNotFoundException("Usuario no encontrado")
                );
    }

    public String saveUser(UserInfo userInfo) {
        userInfo.setPassword(passwordEncoder.encode(userInfo.getPassword()));
        userInfo.setNonLocked(true);
        userInfoRepository.save(userInfo);

        return "Usuario registrado correctamente";
    }
}
