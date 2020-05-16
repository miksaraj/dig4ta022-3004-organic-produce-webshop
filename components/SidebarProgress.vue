<template>
	<div>
		<b-row class="header-row">
			<h2>{{ route === 'index' ? 'Kokonaisedistys' : item.header }}</h2>
		</b-row>
		<b-row class="progress-bar-row">
			<progress-bar :item="item" :bar="true" />
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
	name: 'SidebarProgress',
	components: {
		ProgressBar
	},
	data() {
		return {
			route: null,
			item: null
		}
	},
	watch: {
		$route() {
			this.getRoute()
			this.getItem()
		}
	},
	computed: {
		...mapGetters({
			sectionById: 'sections/sectionById',
			chapterById: 'chapters/chapterById'
		})
	},
	mounted() {
		this.getRoute()
		this.getItem()
	},
	methods: {
		getRoute() {
			this.route = this.$route.name
		},
		getItem() {
			if (this.route === 'chapters-id') {
				this.item = this.chapterById(parseInt(this.$route.params.id))
			} else if (this.route === 'chapters-chapters-id') {
				this.item = this.sectionById(parseInt(this.$route.params.id))
			}
		}
	}
}
</script>
