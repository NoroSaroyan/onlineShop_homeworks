package ru.gb.repository;

import org.springframework.data.repository.CrudRepository;
import ru.gb.entity.Role;

public interface RoleRepository extends CrudRepository<Role, Long> {

    Object findByRole(String userRole);
}