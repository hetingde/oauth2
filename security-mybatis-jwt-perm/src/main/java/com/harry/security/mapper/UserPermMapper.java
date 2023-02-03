package com.harry.security.mapper;

import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserPermMapper {
    List<String> getPermsByUserId(Integer userId);
}
