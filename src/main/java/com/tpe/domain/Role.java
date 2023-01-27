package com.tpe.domain;

import com.tpe.domain.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Enumerated(EnumType.STRING)    // EnumType.STRING şeklinde belirtmezsek enum classından index no ile getirir.
    @Column(length = 30, nullable = false)
    private UserRole name; //


    //"-rollerden user a gitmeyeceksek burada user oluşturmaya gerek yok
    @ManyToMany(mappedBy = "roles")
    private Set<User> users = new HashSet<>();



    @Override
    public String toString() {
        return "Role{" +

                "name=" + name +
                '}';
    }
}
