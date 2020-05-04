<template>
	<div>
		<b-row class="header-row">
			<h2 v-if="route === 'index'">Kokonaisedistys</h2>
		</b-row>
		<b-row class="progress-bar-row">
			<progress-bar :item="item" :subItems="subItems" />
		</b-row>
	</div>
</template>

<style scoped>
.progress-bar-row,
.header-row {
	display: flex;
	justify-content: center;
}

.progress-bar-row div {
	width: 85%;
}
</style>

<script>
import { mapGetters } from 'vuex'
import ProgressBar from '~/components/ProgressBar.vue'
export default {
	name: 'sidebar-progress',
	components: {
		ProgressBar
	},
	data() {
		return {
			route: null,
			subItems: [],
			item: null
		}
	},
	computed: {
		...mapGetters({
			modulesByCourse: 'modules/modulesByCourse',
			courseById: 'courses/courseById'
		})
	},
	mounted() {
		this.getRoute()
		if (this.route !== 'index') {
			this.getCourseById(parseInt(this.$route.params.id))
			this.getSubItems()
		}
	},
	methods: {
		getRoute() {
			if (this.$route.name === 'index') {
				this.route = this.$route.name
			} else if (this.$route.name === 'courses-id') {
				this.route = this.$route.params.id
			}
		},
		getSubItems() {
			this.subItems = this.modulesByCourse(this.item.id)
		},
		getCourseById(id) {
			this.item = this.courseById(id)
		}
	}
}
</script>
