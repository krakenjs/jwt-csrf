'use strict';

if (process.env.NODE_ENV === undefined) {
    process.env.NODE_ENV = 'test';
}

module.exports = function (grunt) {

    var coverageDirectory = 'coverage';

    function isFusion() {
        return process.env.FUSION_BUILD_GENERATED !== undefined;
    }

    var srcFiles = ['*.js', 'apis/**/*.js', 'lib/**/*.js', 'constants/**/*.js'];
    var testFiles = ['test/**/*.js'];
    var allFiles = ['Gruntfile.js'];
    Array.prototype.push.apply(allFiles, srcFiles);
    Array.prototype.push.apply(allFiles, testFiles);

    grunt.initConfig({
        clean: {
            tmp: 'tmp',
            build: '.build',
            coverage: coverageDirectory
        },
        eslint: {
            options: {
                config: '.eslintrc',
                format: isFusion() ? 'checkstyle' : 'stylish',
                outputFile: isFusion() ? 'checkstyle.xml' : ''
            },
            module: [
                'lib/**/*.js'
            ]
        },
        mochatest: {
            src: testFiles,
            options: {
                globals: ['chai'],
                timeout: 60000,
                ignoreLeaks: false,
                ui: 'bdd',
                reporter: isFusion() ? 'xunit-file' : 'spec'
            }
        },
        codecoverage: {
            all: {
                src: testFiles,
                options: {
                    globals: ['chai'],
                    timeout: 1000000,
                    ignoreLeaks: false,
                    ui: 'bdd',
                    reporter: 'dot',
                    covDir: coverageDirectory,
                    reportType: 'lcov',
                    printType: 'both',
                    excludes: ['**/public/**', '**/.build/**', 'Gruntfile.js']
                }
            }
        },
        checkcoverage: {
            options: {
                statements: 90,
                functions: 90,
                branches: 90,
                lines: 95,
                includePattern: coverageDirectory + '/coverage.json'
            }
        }
    });

    // load all grunt tasks matching the `grunt-*` pattern
    require('load-grunt-tasks')(grunt);

    grunt.registerTask('cover', ['coverage']);
    grunt.registerTask('lint', ['eslint']);
    grunt.registerTask('build', ['test']);
    grunt.registerTask('test', ['lint', 'mochatest']);
    grunt.registerTask('coverage', ['clean:coverage', 'codecoverage', 'checkcoverage']);
};
