<template>
	<div>
		<b-row v-if="progress == 100">
			<b-icon icon="check-circle" />
			<p>Suoritettu! {{ done }} / {{ max }}</p>
		</b-row>
		<b-progress v-else-if="progress > 0" :max="max" striped animated>
			<b-progress-bar :value="done">
				<strong>{{ done }} / {{ max }}</strong>
			</b-progress-bar>
		</b-progress>
		<b-button v-else @click="start">
			Aloita!
		</b-button>
	</div>
</template>

<style scoped>
.btn {
	background-color: var(--color-3);
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'progress-bar',
	data() {
		return {
			max: 0,
			done: 0,
			progress: 0
		}
	},
	computed: {
		...mapGetters('progress', ['progressByCourse', 'progressByModule']),
		item() {
			return this.$attrs.item
		},
		subItems() {
			return this.$attrs.subItems
		}
	},
	created() {
		if (!this.item) {
			this.getOverallProgress()
		} else if (!this.item.tasks) {
			this.countTasks()
			this.getDone('course')
		} else {
			this.max = this.item.tasks
			this.getDone('module')
		}
		this.progress = (this.done / this.max) * 100
	},
	methods: {
		getDone(type) {
			let done = []
			if (type === 'course') {
				done = this.progressByCourse(this.item.id)
			} else if (type === 'module') {
				done = this.progressByModule(this.item.id)
			}
			this.done = done.length
		},
		countTasks() {
			for (let i = 0; i < this.subItems.length; i++) {
				this.max = this.max + this.subItems[i].tasks
			}
		},
		getOverallProgress() {
			const modules = this.$store.state.modules.list
			let tasks = 0
			for (let i = 0; i < modules.length; i++) {
				tasks += modules[i].tasks
			}
			this.max = tasks
			this.done = this.$store.state.progress.completed.length
		},
		start() {
			let path = '/'
			if (!this.item.tasks) {
				path = '/courses/' + this.item.id
			} else {
				path = this.$route.path + '/' + this.item.id
			}
			this.$router.push(path)
		}
	}
}
</script>
