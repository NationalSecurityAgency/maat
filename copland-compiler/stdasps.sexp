(LIN SEQ
      ((first (PRIM ((cmd "serialize_graph_asp")
      	      	     (target "/tmp/maatgraphRTttwH")
		     (args ()))))
       (second (LIN SEQ
       	       	    ((first (PRIM ((cmd "compress_asp")
		    	    	   (target "")
				   (args ()))))
		     (second (LIN SEQ
		     	     	  ((first (PRIM ((cmd "encrypt_asp")
				  	  	 (target "/opt/maat/etc/maat/credentials/client.pem")
						 (args ()))))
				   (second (LIN SEQ
				   	   	((first (PRIM ((cmd "create_contract_asp")
							       (target "/tmp/workdir")
							       (args ("/opt/maat/etc/maat/credentials/client.pem" "/opt/maat/etc/maat/credentials/client.key" "PKEYPWORD" 0 1 1)))))
						(second (PRIM ((cmd "send_asp")
							       (target "peerchan")
							       (args ()))))
				   )))
		     )))
       )))
))
