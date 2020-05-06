<template>
	<b-nav vertical>
		<div v-for="item in contentList" :key="item.id">
			<b-nav-item :class="{ dropdown: hasContent(item.id) }">
				<nuxt-link :to="'/courses/' + item.id">
					<h3>{{ item.header }}</h3>
				</nuxt-link>
				<b-navbar-toggle
					v-if="hasContent(item.id)"
					:target="'course-contents-' + item.id"
				>
					<template v-slot:default="{ expanded }">
						<b-icon v-if="expanded" icon="caret-up" />
						<b-icon v-else icon="caret-down" />
					</template>
				</b-navbar-toggle>
			</b-nav-item>
			<b-collapse :id="'course-contents-' + item.id" is-nav>
				<div v-for="part in item.modules" :key="part.id" class="sub">
					<b-nav-item>
						<nuxt-link :to="'/courses/' + item.id + '/' + part.id">
							{{ part.header }}
						</nuxt-link>
					</b-nav-item>
				</div>
			</b-collapse>
		</div>
	</b-nav>
</template>

<style scoped>
.navbar-toggler {
	float: right;
	position: relative;
	top: -38px;
	color: var(--color-4);
}

.nav.flex-column > div {
	margin-bottom: -28px;
}

.nav.flex-column > div > .nav-item:not(.dropdown) {
	margin-bottom: 24px;
}

.sub:first-child {
	margin-top: -8px;
}

.sub:last-child {
	margin-bottom: 32px;
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'sidebar-contents',
	data() {
		return {
			contentList: []
		}
	},
	computed: {
		...mapGetters('modules', ['modulesByCourse']),
		courses() {
			return this.$store.state.courses.list
		}
	},
	mounted() {
		this.getContentList()
	},
	methods: {
		getContentList() {
			for (let i = 0; i < this.courses.length; i++) {
				const modules = this.modulesByCourse(this.courses[i].id)
				this.contentList.push({
					id: this.courses[i].id,
					header: this.courses[i].header,
					modules
				})
			}
		},
		hasContent(id) {
			const course = this.contentList.find(element => element.id === id)
			if (course.modules.length > 0) {
				return true
			}
			return false
		}
	}
}
</script>
