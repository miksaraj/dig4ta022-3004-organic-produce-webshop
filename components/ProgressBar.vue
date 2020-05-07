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
	name: 'progressBar',
	data() {
		return {
			max: 0,
			done: 0,
			progress: 0
		}
	},
	computed: {
		...mapGetters('progress', ['progressByChapter', 'progressBySection']),
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
		} else if (!this.item.assignments) {
			this.countAssignments()
			this.getDone('chapter')
		} else {
			this.max = this.item.assignments
			this.getDone('section')
		}
		this.progress = (this.done / this.max) * 100
	},
	methods: {
		getDone(type) {
			let done = []
			if (type === 'chapter') {
				done = this.progressByChapter(this.item.id)
			} else if (type === 'section') {
				done = this.progressBySection(this.item.id)
			}
			this.done = done.length
		},
		countAssignments() {
			for (let i = 0; i < this.subItems.length; i++) {
				this.max = this.max + this.subItems[i].assignments
			}
		},
		getOverallProgress() {
			const sections = this.$store.state.sections.list
			let assignments = 0
			for (let i = 0; i < sections.length; i++) {
				assignments += sections[i].assignments
			}
			this.max = assignments
			this.done = this.$store.state.progress.completed.length
		},
		start() {
			let path = '/'
			if (!this.item.assignments) {
				path = '/chapters/' + this.item.id
			} else {
				path = this.$route.path + '/' + this.item.id
			}
			this.$router.push(path)
		}
	}
}
</script>
