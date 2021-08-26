/\${APB_INSTALL_DIR}/{ 
    gsub("\\${APB_INSTALL_DIR}", apbdir)
}

/\${ASP_INSTALL_DIR}/{
    gsub("\\${ASP_INSTALL_DIR}", aspdir)
}

/\${SPEC_INSTALL_DIR}/{
    gsub("\\${SPEC_INST_DIR}", specdir)
}

/\${MAAT_USER}/{
    gsub("\\${MAAT_USER}", maatuser)
}

/\${MAAT_GROUP}/{
    gsub("\\${MAAT_GROUP}", maatgroup)
}

{
    print $0;
}
