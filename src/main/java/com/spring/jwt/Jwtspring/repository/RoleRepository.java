package com.spring.jwt.Jwtspring.repository;

import com.spring.jwt.Jwtspring.entity.Role;
import com.spring.jwt.Jwtspring.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {
    Role findByName(String name);
}
