# Bibliophile

package job.portal.exceptions;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message) {
        super(message);
    }
}
--------

package job.portal.exceptions;

public class RoleValidationException extends RuntimeException {
    public RoleValidationException(String message) {
        super(message);
    }
}
------------

package job.portal.exceptions;

public class RoleNotFoundException extends RuntimeException {
    public RoleNotFoundException(String message) {
        super(message);
    }
}
---------------

package job.portal.exceptions;

public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}
------------

package job.portal.exceptions;

public class InvalidPasswordException extends RuntimeException  {

    public InvalidPasswordException(String message) {
        super(message);
    }
}
-----------

package job.portal.exceptions;

public class FileStorageException extends RuntimeException {
    public FileStorageException(String message) {
        super(message);
    }
}
-----------------
package job.portal.exceptions;

import job.portal.dto.ApiError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RoleValidationException.class)
    public ResponseEntity<ApiError> handleRoleException(RoleValidationException ex, WebRequest request) {
        ApiError error = ApiError.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Role Error")
                .message(ex.getMessage())
                .build();
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<String> handleRuntime(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleAll(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal error: " + ex.getMessage());
    }

    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<String> handleRoleNotFound(RoleNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleUserNotFoundException(UserNotFoundException ex) {
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "User Not Found");
        errorResponse.put("message", ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(InvalidPasswordException.class)
    public ResponseEntity<Map<String, String>> handleInvalidPassword(InvalidPasswordException ex) {
        Map<String, String> error = new HashMap<>();
        error.put("error", "Invalid Password");
        error.put("message", ex.getMessage());
        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }
}
----------
SERVICES----

package job.portal.services;

import jakarta.persistence.EntityNotFoundException;
import job.portal.dto.UserDetailsDTO;
import job.portal.dto.UserRegisterDTO;
import job.portal.entities.Role;
import job.portal.entities.User;
import job.portal.exceptions.RoleNotFoundException;
import job.portal.exceptions.UserNotFoundException;
import job.portal.mappers.UserMapper;
import job.portal.repositories.RoleRepository;
import job.portal.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    public User registerUser(UserRegisterDTO registrationDto) {

        Role role = (Role) roleRepository.findByRoleName(registrationDto.getRoleName())
                .orElseThrow(() -> new RuntimeException("Role not found"));

        User user = new User();
        user.setUsername(registrationDto.getUsername());
        user.setPassword(new BCryptPasswordEncoder().encode(registrationDto.getPassword()));
        user.setEmail(registrationDto.getEmail());
        user.setPhoneNo(registrationDto.getPhoneNo());
        user.setCreatedAt(LocalDateTime.now());
        user.setRole(role);

        return userRepository.save(user);
    }

    public List<UserDetailsDTO> getAllUsers() {
        List<User> users = userRepository.findAll();

        return users.stream()
                .map(u -> new UserDetailsDTO(
                        u.getUserId(),
                        u.getUsername(),
                        u.getEmail(),
                        u.getPhoneNo(),
                        u.getRole().getRoleName()
                ))
                .toList();
    }

    public UserDetailsDTO getUserById(Integer id) {
        return userRepository.findById(Long.valueOf(id))
                .map(UserMapper::toDTO)
                .orElseThrow(()->new RuntimeException("User Not Found"));
    }

    public void deleteUserById(Integer id) {

        Long userId = Long.valueOf(id);
        if (!userRepository.existsById(userId)) {
            throw new UserNotFoundException("User not found with id: " + id);
        }
        userRepository.deleteById(userId);

    }


    public UserDetailsDTO updateUser(Integer id, UserDetailsDTO updateDTO) {
        User user = userRepository.findById(Long.valueOf(id))
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));

        user.setUsername(updateDTO.getUsername());
        user.setEmail(updateDTO.getEmail());

        Role role = (Role) roleRepository.findByRoleName(updateDTO.getRoleName())
                .orElseThrow(() -> new RoleNotFoundException("Role not found: " + updateDTO.getRoleName()));
        user.setRole(role);

        User updatedUser = userRepository.save(user);
        return UserMapper.toDTO(updatedUser);
    }


    public boolean isRoleAssignedToAnyUser(int roleId) {
        return userRepository.existsByRoleRoleId(roleId);
    }
}

--------------
package job.portal.services;

import job.portal.dto.RoleDTO;
import job.portal.entities.Role;
import job.portal.exceptions.RoleNotFoundException;
import job.portal.mappers.RoleMapper;
import job.portal.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import job.portal.exceptions.RoleValidationException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Arrays;
import java.util.Map;


import java.util.List;

@Service
public class RoleService {

    @Autowired
    private RoleRepository roleRepository;

    private RoleService roleService;

    private final List<String> allowedRoles = Arrays.asList("Admin", "Employer", "Job Seeker");

    @PostMapping
    public Role createRole(Role role) {
        if (roleRepository.count() >= 3) {
            throw new RoleValidationException("Maximum of 3 roles allowed: Admin, Employer, Job Seeker.");
        }

        if (!allowedRoles.contains(role.getRoleName())) {
            throw new RoleValidationException("Only Admin, Employer, or Job Seeker roles are allowed.");
        }

        if (roleRepository.findByRoleNameIgnoreCase(role.getRoleName()).isPresent()) {
            throw new RoleValidationException("Role '" + role.getRoleName() + "' already exists.");
        }

        switch (role.getRoleName()) {
            case "Admin" -> role.setRoleId(1L);
            case "Employer" -> role.setRoleId(2L);
            case "Job Seeker" -> role.setRoleId(3L);
        }

        return roleRepository.save(role);
    }

    @GetMapping
    public List<RoleDTO> getAllRoles(){
        List<Role> roles = roleRepository.findAll();

        List<RoleDTO> roleDTOList = roles.stream()
                .map(r -> new RoleDTO(r.getRoleId(), r.getRoleName()))
                .toList();

        return roleDTOList;
    }

    @GetMapping
    public RoleDTO getRoleById(Integer id){
        return roleRepository.findById(id)
                .map(RoleMapper::toDTO)
                .orElseThrow(() -> new RuntimeException("Only " + roleRepository.count() + " roles are available."));


    }

    @DeleteMapping
    public boolean deleteRole(int id){
        if (!roleRepository.existsById(id)) {
            long totalRoles = roleRepository.count();
            throw new RoleNotFoundException("Role with id " + id + " and above not found. Only " + totalRoles + " roles are available.");
        }
        if(roleRepository.existsById(id)){
            roleRepository.deleteById(id);
            return true;
        }
        return false;
    }
}
----------------------------
package job.portal.services;

import job.portal.dto.UserLoginDTO;
import job.portal.entities.User;
import job.portal.exceptions.InvalidPasswordException;
import job.portal.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String loginUser(UserLoginDTO loginDTO) {
        Optional<User> optionalUser = userRepository.findByUsername(loginDTO.getUsername());

        if (optionalUser.isEmpty()) {
            return "User not found. Please register first.";
        }

        User user = optionalUser.get();

        boolean passwordMatch = passwordEncoder.matches(loginDTO.getPassword(), user.getPassword());

        if (passwordMatch) {
            return "Login successful!";
        } else {
            throw new InvalidPasswordException("Incorrect password. Please check your password.");
        }
    }
}

REPO------------

package job.portal.repositories;

import job.portal.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    boolean existsByEmail(String email);

    Optional<User> findById(Long id);

    boolean existsByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByRoleRoleId(int roleId);


//    Optional<Object> findById(Long userId);
}
-----------------------
package job.portal.repositories;

import job.portal.entities.Role;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRoleNameIgnoreCase(String roleName);

    Optional<Object> findByRoleName(String roleName);
}
------------------
MAPPER----------

package job.portal.mappers;

import job.portal.dto.UserDetailsDTO;
import job.portal.dto.UserRegisterDTO;
import job.portal.entities.Role;
import job.portal.entities.User;

import java.time.LocalDateTime;

public class UserMapper {

    public static User toEntity(UserRegisterDTO
                                        dto, Role role) {
        User user = new User();
        user.setUsername(dto.getUsername());
        user.setPassword(dto.getPassword());
        user.setEmail(dto.getEmail());
        user.setPhoneNo(dto.getPhoneNo());
        user.setCreatedAt(LocalDateTime.now());
        user.setRole(role);
        return user;
    }

    public static UserDetailsDTO toDTO(User user) {
        UserDetailsDTO dto = new UserDetailsDTO();
        dto.setUserId(user.getUserId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setPhoneNo(user.getPhoneNo());
        dto.setRoleName(user.getRole().getRoleName());
        dto.setRoleName(user.getRole() != null ? user.getRole().getRoleName() : null);

//        if (user.getJobSeeker() != null) {
//            dto.setPreferences(user.getJobSeeker().getPreferences());
//        }
        return dto;
    }
}
------------------
package job.portal.mappers;

import job.portal.dto.RoleDTO;
import job.portal.entities.Role;

public class RoleMapper {

    public static RoleDTO toDTO(Role role){
        return new RoleDTO(role.getRoleId(), role.getRoleName());
    }

    public static Role toEntity(RoleDTO roleDTO){
        Role role = new Role();
        role.setRoleId(roleDTO.getRoleId());
        role.setRoleName(roleDTO.getRoleName());
        return role;
    }
}
-----------
ENTITY---------------

package job.portal.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;


    @Column(name = "email_id", nullable = false, unique = true)
    private String email;

    private String phoneNo;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();


    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    //reverse map here to get the details when login as admin/emplpoyer
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    private JobSeekers jobSeeker;

}
-----------------------
package job.portal.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name="roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Role {

    @Id
    @Column(name = "role_id")
    private Long roleId;

    @Column(name = "role_name", nullable = false, unique = true, length = 50)
    private String roleName;
}

----------
DTO---------

package job.portal.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserRegisterDTO {

    private String username;
    private String password;
    private String email;
    private String phoneNo;
    private String roleName;
}
-------------
package job.portal.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserLoginDTO {

    private String username;
    private String password;
}
--------
package job.portal.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserDetailsDTO {

    Long userId;
    private String username;
    private String email;
    private String phoneNo;
    private String roleName;
}
---------------
package job.portal.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RoleDTO {

    private Long roleId;
    private String roleName;
}
--------------
package job.portal.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiError<T> {
    private LocalDateTime timestamp;
    private int status;
    private String error;
    private String message;

}
------------
CONTROLLER-----------

package job.portal.controllers;

import job.portal.dto.UserLoginDTO;
import job.portal.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserLoginDTO loginDTO) {
        String response = authService.loginUser(loginDTO);

        if (response.equals("Login successful!")) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
}
---------------------
package job.portal.controllers;

import job.portal.dto.UserDetailsDTO;
import job.portal.dto.UserRegisterDTO;
import job.portal.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserRegisterDTO registrationDto) {
        userService.registerUser(registrationDto);
        return ResponseEntity.ok("User registered successfully");
    }

    @GetMapping
    public ResponseEntity<List<UserDetailsDTO>> getAllUsers(){
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDetailsDTO> getUserById(@PathVariable int id) {
        UserDetailsDTO userDetailsDTO = userService.getUserById(id);
        return userDetailsDTO != null
                ? ResponseEntity.ok(userDetailsDTO)
                : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Integer id) {
        userService.deleteUserById(id);
        return ResponseEntity.ok("User deleted successfully");
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserDetailsDTO> updateUser(@PathVariable Integer id, @RequestBody UserDetailsDTO updateDTO) {
        UserDetailsDTO updatedUser = userService.updateUser(id, updateDTO);
        return ResponseEntity.ok(updatedUser);
    }
}
-------------------------------
package job.portal.controllers;

import job.portal.dto.RoleDTO;
import job.portal.entities.Role;
import job.portal.repositories.UserRepository;
import job.portal.services.RoleService;
import job.portal.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static job.portal.repositories.UserRepository.*;

@RestController
@RequestMapping("/api/role")
public class RoleController {

    @Autowired
    private RoleService roleService ;

    @Autowired
    private UserService userService;

    @PostMapping
    public ResponseEntity<Role> createRole(@RequestBody Role role){
        return ResponseEntity.ok(roleService.createRole(role));
    }

    @GetMapping
    public ResponseEntity<List<RoleDTO>> getAllRoles(){
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @GetMapping("/{id}")
    public ResponseEntity<RoleDTO> getRoleById(@PathVariable int id){
        RoleDTO roleDTO = roleService.getRoleById(id);
        return roleDTO != null ? ResponseEntity.ok(roleDTO) : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRole(@PathVariable int id){

        boolean isRoleInUse = userService.isRoleAssignedToAnyUser(id);

        if (isRoleInUse) {
            throw new IllegalStateException("Cannot delete role. It is still assigned to users.");
        }

        boolean deleted = roleService.deleteRole(id);
        return deleted ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }
}
-------------------
SECURITY CONFIG----------

package job.portal.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.repository.query.parser.Part;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        HttpSecurity logout =
                http
                        .csrf(csrf -> csrf.disable())
                        .authorizeHttpRequests(authRequests -> authRequests
                                .requestMatchers("/api/users/register", "/api/users/login").permitAll()
                                .requestMatchers("/api/users/**").permitAll()
                                        .requestMatchers("/api/role/**").permitAll()
                                .requestMatchers("/admin/**").hasRole("Admin")
//                                .requestMatchers("/employer/**").hasRole("Employer")
                                .requestMatchers("api/employers/**").permitAll()
//                                .requestMatchers("/jobseeker/**").hasRole("Job Seeker")
                                        .requestMatchers("/jobseeker/**").permitAll()
                                .anyRequest().authenticated()
                        )
                        .formLogin(withDefaults())
                        .logout(withDefaults());


        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var userDetailsService = new InMemoryUserDetailsManager();

        var admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("adminPass")
                .roles("Admin")
                .build();

        userDetailsService.createUser(admin);

        return userDetailsService;
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

