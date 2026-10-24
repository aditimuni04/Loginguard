# Third-party software

LoginGuard bundles these libraries in `third_party/`. They are not my work and keep their own licenses.

| Library | Version | Use | License |
| --- | --- | --- | --- |
| [cpp-httplib](https://github.com/yhirose/cpp-httplib) (Yuji Hirose) | 0.18.3 | HTTP server for the API and dashboard | MIT |
| [nlohmann/json](https://github.com/nlohmann/json) (Niels Lohmann) | 3.11.3 | JSON parsing and output | MIT |
| [SQLite](https://www.sqlite.org/) amalgamation | 3.38.2 | Database engine (used only if no system SQLite is found) | Public domain |

The MIT license text for each MIT-licensed library is in the header of its source file under `third_party/`.
