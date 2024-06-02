package at.schoolist.edgeservice.web.dto;

import java.util.List;
import java.util.UUID;

public record User(
		UUID id,
		String username,
		String firstName,
		String lastName,
		List<String> roles
){}