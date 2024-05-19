package at.schoolist.edgeservice.user;

import java.util.Collection;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@Slf4j
public class UserController {

  private static final String REALM_ACCESS_CLAIM = "realm_access";
  private static final String ROLES_CLAIM = "roles";

  @GetMapping("user")
  public Mono<User> getUser(@AuthenticationPrincipal OidcUser oidcUser) {
    var realmAccess = oidcUser.getClaimAsMap(REALM_ACCESS_CLAIM);
    var roles = (Collection<String>) realmAccess.get(ROLES_CLAIM);

    log.info("Fetching information about the currently authenticated user");
    var user = new User(
        oidcUser.getPreferredUsername(),
        oidcUser.getGivenName(),
        oidcUser.getFamilyName(),
        roles.stream().toList()
    );
    return Mono.just(user);
  }

}
