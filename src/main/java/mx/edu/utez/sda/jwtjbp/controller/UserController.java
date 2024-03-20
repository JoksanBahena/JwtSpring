package mx.edu.utez.sda.jwtjbp.controller;

import mx.edu.utez.sda.jwtjbp.entity.AuthRequest;
import mx.edu.utez.sda.jwtjbp.entity.UserInfo;
import mx.edu.utez.sda.jwtjbp.service.JwtService;
import mx.edu.utez.sda.jwtjbp.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {
    @Autowired
    private UserInfoService userInfoService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/index")
    public String index() {
        return "Servicio index";
    }

    @PostMapping("/save")
    public String register(@RequestBody UserInfo userInfo) {
        return userInfoService.saveUser(userInfo);
    }

    @GetMapping("/admin/test")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String onlyAdmin() {
        return "Endpoint solo pa admins";
    }

    @GetMapping("/user/test")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    public String onlyUser() {
        return "Endpoint solo pa user y admin";
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest authRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getUsername(),
                            authRequest.getPassword()
                    )
            );

            if(authentication.isAuthenticated()) {
                return jwtService.generateToken(authRequest.getUsername());
            } else {
                throw new UsernameNotFoundException("Usuario invalido");
            }
        }catch (Exception e) {
            throw new UsernameNotFoundException("Usuario invalido");
        }
    }
}
