var gulp = require('gulp');
var gutil = require('gulp-util');
var concat = require('gulp-concat');
var uglify = require('gulp-uglify');
var rename = require('gulp-rename');
var coffee = require('gulp-coffee');
var cache = require('gulp-cached');
var remember = require('gulp-remember');
var header = require('gulp-header');
var footer = require('gulp-footer');
var plumber = require('gulp-plumber');

/* Engine build tasks */
task = {
	source: "src/*.coffee",
	target: {
		path: "compiled",
		name: "circd.js"
	}
}

gulp.task('dev', function() {
	return gulp.src(task.source)
		.pipe(plumber())
		.pipe(cache("coffee"))
		.pipe(coffee({bare: true}).on('error', gutil.log)).on('data', gutil.log)
		.pipe(remember("coffee"))
		.pipe(concat("coffee.js"))
		.pipe(header('(function () {'))
		.pipe(footer('; })();'))
		.pipe(rename(task.target.name))
		.pipe(gulp.dest(task.target.path));
});


/* Watcher */
gulp.task('watch', function () {
	var watcher = gulp.watch(task.source, ['dev']);
	watcher.on('change', function (event) {
		if (event.type === 'deleted')
		{
			delete cache.caches['coffee'][event.path];
			remember.forget('coffee', event.path);
		}
	});

	/* Initial build */
	gulp.start("dev");
});

gulp.task("default", ["dev"]);
