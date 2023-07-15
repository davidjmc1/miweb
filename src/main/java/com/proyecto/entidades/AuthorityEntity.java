package com.proyecto.entidades;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.ToString;

@Entity
@Table(name = "TBL_AUTHORITY", schema = "esq_security")
@ToString
@Data
public class AuthorityEntity{

	@Id
	@Column(name = "AUTHORITY_ID") 
	private Long id = 0L;

	@Column(name = "NOMBRE")
	private String nombre = "";

}
