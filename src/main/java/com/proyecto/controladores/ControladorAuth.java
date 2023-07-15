package com.proyecto.controladores;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.proyecto.servicio.UserDetails.UserDetailsImpl;
import com.proyecto.servicio.UserDetails.UserDetailsServiceImpl;
import com.proyecto.util.JWTUtils;
import com.proyecto.util.request.AuthenticationRequest;
import com.proyecto.util.response.AuthenticationResponse;
import com.proyecto.util.response.ValidateTokenResponse;

@RestController
@RequestMapping(value = "/auth")
@CrossOrigin(origins = "*", methods = { RequestMethod.GET, RequestMethod.POST })
public class ControladorAuth {

	private AuthenticationManager authenticationManager;

	//private UserDetailsService userDetailsServiceImpl;
	private UserDetailsServiceImpl userDetailsServiceImpl;
	
	private JWTUtils jWTUtils;

	public ControladorAuth(AuthenticationManager authenticationManager, UserDetailsServiceImpl userDetailsServiceImpl, JWTUtils jWTUtils) {
		this.authenticationManager = authenticationManager;
		this.userDetailsServiceImpl = userDetailsServiceImpl;
		this.jWTUtils = jWTUtils;
	}
	  
	  
	  //private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	  

	  @PostMapping("/authenticate")
	  public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest authenticationReq) {
		  
	    authenticationManager.authenticate(
	        new UsernamePasswordAuthenticationToken(authenticationReq.getUsuario(),
	            authenticationReq.getContrasena()));
	    
	    //final UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(
	        //authenticationReq.getUsername());
	    
	    final UserDetailsImpl userDetails = userDetailsServiceImpl.getUserDetail(authenticationReq.getUsuario());
	    
	    final String jwt = jWTUtils.generateJwtToken(userDetails);

	    return ResponseEntity.ok(
	    		  AuthenticationResponse.builder()
	    		  .codeStatus(HttpStatus.OK.value())
	    		  .message("OK")
	    		  .accessToken(jwt)
	    		  .build()
	    		  );
	 
	  }
	  
	  @PostMapping("/refresh-token")
	  public ResponseEntity<AuthenticationResponse> refreshToken(@RequestHeader("Authorization") String authorization) {
		  
		  if (!StringUtils.hasText(authorization) || !authorization.startsWith("Bearer ")) {
			  System.out.println("----> 1");
			  return ResponseEntity.ok(
		    		  AuthenticationResponse.builder()
		    		  .codeStatus(HttpStatus.BAD_REQUEST.value())
		    		  .message("Empty JWT token")
		    		  .build()
		    		  );
		  }
		  
		  String tokenRequest = authorization.substring(7);
		  //String tokenRequest headerAuth.substring(7, headerAuth.length());
		  
		  ValidateTokenResponse vt = jWTUtils.validateJwtToken(tokenRequest);
		  
		  if (tokenRequest == null || !vt.isValid()) {
			  System.out.println("----> 2");
			  return ResponseEntity.ok(
		    		  AuthenticationResponse.builder()
		    		  .codeStatus(HttpStatus.BAD_REQUEST.value())
		    		  .message(vt.isValid()? "JWT token is null": vt.getMessage())
		    		  .build()
		    		  );
		  }
		  
		  final String username = jWTUtils.getUserNameFromJwtToken(tokenRequest);
		  
		  final UserDetailsImpl userDetails = userDetailsServiceImpl.getUserDetail(username);
		  
		  final String jwtRefresh = jWTUtils.generateJwtToken(userDetails);
	       
	      return ResponseEntity.ok(
	    		  AuthenticationResponse.builder()
	    		  .codeStatus(HttpStatus.OK.value())
	    		  .message("OK")
	    		  .refreshToken(jwtRefresh)
	    		  .build()
	    		  );
	  }
}
