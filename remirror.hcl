listen = ":8080"
data = "/var/remirror"
host = "http://localhost:8080"
upstream_timeout = "200ms"

mirrors {
	mirror {
		prefix = "/archlinux/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "\\.(db|files|db\\.sig|files\\.sig)(\\.tar\\.(gz|xz|zst))?$" action = "try" }
			match { pattern = "/.*\\.links\\.tar\\.gz$" action = "try" }
		}
	}

	mirror {
		prefix = "/centos/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/repodata/.*\\.(xml|sqlite)(\\.gz|\\.bz2|\\.xz)?$" action = "try" }
			match { pattern = "/(repomd\\.xml|TRANS\\.TBL)$" action = "try" }
		}
	}

	mirror {
		prefix = "/fedora/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/repodata/.*\\.(xml|sqlite)(\\.gz|\\.bz2|\\.xz)?$" action = "try" }
			match { pattern = "/(repomd\\.xml|TRANS\\.TBL)$" action = "try" }
		}
	}

	mirror {
		prefix = "/fedora-epel/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/repodata/.*\\.(xml|sqlite)(\\.gz|\\.bz2|\\.xz)?$" action = "try" }
			match { pattern = "/(repomd\\.xml|TRANS\\.TBL)$" action = "try" }
		}
	}

	mirror {
		prefix = "/ubuntu/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = "/(Packages|Sources|Contents-.*|Release|InRelease)(\\.gz|\\.bz2|\\.xz)?$" action = "try" }
			match { pattern = "/by-hash/.*$" action = "try" }
		}
	}

	mirror {
		prefix = "/ubuntu-cd/"
		upstream = "https://mirrors.xmission.com"
		matches {
			match { pattern = ".*/SHA256SUMS.*" action = "try" }
			}
	}

	mirror {
		# export GOPROXY="http://localhost:8080/golang"
		# export GOSUMDB="off"
		prefix = "/golang/"
		upstream = "https://storage.googleapis.com"
	}

	mirror {
		# export PUB_HOSTED_URL="http://localhost:8080/pub.dev"
		prefix = "/pub.dev/"
		upstream = "https://pub.dev/"
		strip_prefix = true
		matches {
			match { pattern = "/api/packages/.*" action = "try" rewrite = true }
		}
	}

	mirror {
		# npm registry
		# export npm_config_registry="http://localhost:8080/npm"
		prefix = "/npm/"
		upstream = "https://registry.npmjs.org/"
		strip_prefix = true
		matches {
			match { pattern = "/.*\\.tgz$" action = "cache" }
			match { pattern = "/-/.*" action = "try" }
			match { pattern = "/[^/]+$" action = "try" rewrite = true }
		}
	}

	mirror {
		# PyPI - Python Package Index
		# pip install -i http://localhost:8080/pypi/simple package_name
		# or add to ~/.pip/pip.conf: index-url = http://localhost:8080/pypi/simple
		prefix = "/pypi/"
		upstream = "https://pypi.org"
		strip_prefix = true
		matches {
			match { pattern = "/packages/.*\\.(whl|tar\\.gz|zip)$" action = "cache" }
			match { pattern = "/pypi/.*" action = "try" }
			match { pattern = "/simple/.*" action = "try" }
		}
	}
}
